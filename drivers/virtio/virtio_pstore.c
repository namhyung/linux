#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pstore.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_pstore.h>

#define VIRT_PSTORE_ORDER    2
#define VIRT_PSTORE_BUFSIZE  (4096 << VIRT_PSTORE_ORDER)
#define VIRT_PSTORE_NR_REQ   128

struct virtio_pstore {
	struct virtio_device	*vdev;
	struct virtqueue	*vq[2];
	struct pstore_info	 pstore;
	struct virtio_pstore_req req[VIRT_PSTORE_NR_REQ];
	struct virtio_pstore_res res[VIRT_PSTORE_NR_REQ];
	unsigned int		 req_id;

	/* Waiting for host to ack */
	wait_queue_head_t	acked;
	int			failed;
};

#define TYPE_TABLE_ENTRY(_entry)				\
	{ PSTORE_TYPE_##_entry, VIRTIO_PSTORE_TYPE_##_entry }

struct type_table {
	int pstore;
	u16 virtio;
} type_table[] = {
	TYPE_TABLE_ENTRY(DMESG),
};

#undef TYPE_TABLE_ENTRY


static u16 to_virtio_type(struct virtio_pstore *vps, enum pstore_type_id type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(type_table); i++) {
		if (type == type_table[i].pstore)
			return cpu_to_virtio16(vps->vdev, type_table[i].virtio);
	}

	return cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_TYPE_UNKNOWN);
}

static enum pstore_type_id from_virtio_type(struct virtio_pstore *vps, u16 type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(type_table); i++) {
		if (virtio16_to_cpu(vps->vdev, type) == type_table[i].virtio)
			return type_table[i].pstore;
	}

	return PSTORE_TYPE_UNKNOWN;
}

static void virtpstore_ack(struct virtqueue *vq)
{
	struct virtio_pstore *vps = vq->vdev->priv;

	wake_up(&vps->acked);
}

static void virtpstore_check(struct virtqueue *vq)
{
	struct virtio_pstore *vps = vq->vdev->priv;
	struct virtio_pstore_res *res;
	unsigned int len;

	res = virtqueue_get_buf(vq, &len);
	if (res == NULL)
		return;

	if (virtio32_to_cpu(vq->vdev, res->ret) < 0)
		vps->failed = 1;
}

static void virt_pstore_get_reqs(struct virtio_pstore *vps,
				 struct virtio_pstore_req **preq,
				 struct virtio_pstore_res **pres)
{
	unsigned int idx = vps->req_id++ % VIRT_PSTORE_NR_REQ;

	*preq = &vps->req[idx];
	*pres = &vps->res[idx];

	memset(*preq, 0, sizeof(**preq));
	memset(*pres, 0, sizeof(**pres));
}

static int virt_pstore_open(struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_req *req;
	struct virtio_pstore_res *res;
	struct scatterlist sgo[1], sgi[1];
	struct scatterlist *sgs[2] = { sgo, sgi };
	unsigned int len;

	virt_pstore_get_reqs(vps, &req, &res);

	req->cmd = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_OPEN);

	sg_init_one(sgo, req, sizeof(*req));
	sg_init_one(sgi, res, sizeof(*res));
	virtqueue_add_sgs(vps->vq[0], sgs, 1, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq[0]);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq[0], &len));
	return virtio32_to_cpu(vps->vdev, res->ret);
}

static int virt_pstore_close(struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_req *req = &vps->req[vps->req_id];
	struct virtio_pstore_res *res = &vps->res[vps->req_id];
	struct scatterlist sgo[1], sgi[1];
	struct scatterlist *sgs[2] = { sgo, sgi };
	unsigned int len;

	virt_pstore_get_reqs(vps, &req, &res);

	req->cmd = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_CLOSE);

	sg_init_one(sgo, req, sizeof(*req));
	sg_init_one(sgi, res, sizeof(*res));
	virtqueue_add_sgs(vps->vq[0], sgs, 1, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq[0]);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq[0], &len));
	return virtio32_to_cpu(vps->vdev, res->ret);
}

static ssize_t virt_pstore_read(u64 *id, enum pstore_type_id *type,
				int *count, struct timespec *time,
				char **buf, bool *compressed,
				ssize_t *ecc_notice_size,
				struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_req *req;
	struct virtio_pstore_res *res;
	struct virtio_pstore_fileinfo info;
	struct scatterlist sgo[1], sgi[3];
	struct scatterlist *sgs[2] = { sgo, sgi };
	unsigned int len;
	unsigned int flags;
	int ret;
	void *bf;

	virt_pstore_get_reqs(vps, &req, &res);

	req->cmd = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_READ);

	sg_init_one(sgo, req, sizeof(*req));
	sg_init_table(sgi, 3);
	sg_set_buf(&sgi[0], res, sizeof(*res));
	sg_set_buf(&sgi[1], &info, sizeof(info));
	sg_set_buf(&sgi[2], psi->buf, psi->bufsize);
	virtqueue_add_sgs(vps->vq[0], sgs, 1, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq[0]);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq[0], &len));
	if (len < sizeof(*res) + sizeof(info))
		return -1;

	ret = virtio32_to_cpu(vps->vdev, res->ret);
	if (ret < 0)
		return ret;

	len = virtio32_to_cpu(vps->vdev, info.len);

	bf = kmalloc(len, GFP_KERNEL);
	if (bf == NULL)
		return -ENOMEM;

	*id    = virtio64_to_cpu(vps->vdev, info.id);
	*type  = from_virtio_type(vps, info.type);
	*count = virtio32_to_cpu(vps->vdev, info.count);

	flags = virtio32_to_cpu(vps->vdev, info.flags);
	*compressed = flags & VIRTIO_PSTORE_FL_COMPRESSED;

	time->tv_sec  = virtio64_to_cpu(vps->vdev, info.time_sec);
	time->tv_nsec = virtio32_to_cpu(vps->vdev, info.time_nsec);

	memcpy(bf, psi->buf, len);
	*buf = bf;

	return len;
}

static int notrace virt_pstore_write(enum pstore_type_id type,
				     enum kmsg_dump_reason reason,
				     u64 *id, unsigned int part, int count,
				     bool compressed, size_t size,
				     struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_req *req;
	struct virtio_pstore_res *res;
	struct scatterlist sgo[2], sgi[1];
	struct scatterlist *sgs[2] = { sgo, sgi };
	unsigned int flags = compressed ? VIRTIO_PSTORE_FL_COMPRESSED : 0;

	*id = vps->req_id;
	virt_pstore_get_reqs(vps, &req, &res);

	req->cmd   = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_WRITE);
	req->type  = to_virtio_type(vps, type);
	req->flags = cpu_to_virtio32(vps->vdev, flags);

	sg_init_table(sgo, 2);
	sg_set_buf(&sgo[0], req, sizeof(*req));
	sg_set_buf(&sgo[1], pstore_get_buf(psi), size);
	sg_init_one(sgi, res, sizeof(*res));
	virtqueue_add_sgs(vps->vq[1], sgs, 1, 1, vps, GFP_ATOMIC);
	virtqueue_kick(vps->vq[1]);

	return 0;
}

static int virt_pstore_erase(enum pstore_type_id type, u64 id, int count,
			     struct timespec time, struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_req *req;
	struct virtio_pstore_res *res;
	struct scatterlist sgo[1], sgi[1];
	struct scatterlist *sgs[2] = { sgo, sgi };
	unsigned int len;

	virt_pstore_get_reqs(vps, &req, &res);

	req->cmd   = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_ERASE);
	req->type  = to_virtio_type(vps, type);
	req->id	   = cpu_to_virtio64(vps->vdev, id);
	req->count = cpu_to_virtio32(vps->vdev, count);

	sg_init_one(sgo, req, sizeof(*req));
	sg_init_one(sgi, res, sizeof(*res));
	virtqueue_add_sgs(vps->vq[0], sgs, 1, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq[0]);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq[0], &len));
	return virtio32_to_cpu(vps->vdev, res->ret);
}

static int virt_pstore_init(struct virtio_pstore *vps)
{
	struct pstore_info *psinfo = &vps->pstore;
	int err;

	if (!psinfo->bufsize)
		psinfo->bufsize = VIRT_PSTORE_BUFSIZE;

	psinfo->buf = alloc_pages_exact(psinfo->bufsize, GFP_KERNEL);
	if (!psinfo->buf) {
		pr_err("cannot allocate pstore buffer\n");
		return -ENOMEM;
	}

	psinfo->owner = THIS_MODULE;
	psinfo->name  = "virtio";
	psinfo->open  = virt_pstore_open;
	psinfo->close = virt_pstore_close;
	psinfo->read  = virt_pstore_read;
	psinfo->erase = virt_pstore_erase;
	psinfo->write = virt_pstore_write;
	psinfo->flags = PSTORE_FLAGS_DMESG;

	psinfo->data  = vps;
	spin_lock_init(&psinfo->buf_lock);

	err = pstore_register(psinfo);
	if (err)
		kfree(psinfo->buf);

	return err;
}

static int virt_pstore_exit(struct virtio_pstore *vps)
{
	struct pstore_info *psinfo = &vps->pstore;

	pstore_unregister(psinfo);

	free_pages_exact(psinfo->buf, psinfo->bufsize);
	psinfo->buf = NULL;
	psinfo->bufsize = 0;

	return 0;
}

static int virtpstore_init_vqs(struct virtio_pstore *vps)
{
	vq_callback_t *callbacks[] = { virtpstore_ack, virtpstore_check };
	const char *names[] = { "pstore_read", "pstore_write" };

	return vps->vdev->config->find_vqs(vps->vdev, 2, vps->vq,
					   callbacks, names);
}

static void virtpstore_init_config(struct virtio_pstore *vps)
{
	u32 bufsize;

	virtio_cread(vps->vdev, struct virtio_pstore_config, bufsize, &bufsize);

	vps->pstore.bufsize = PAGE_ALIGN(bufsize);
}

static void virtpstore_confirm_config(struct virtio_pstore *vps)
{
	u32 bufsize = vps->pstore.bufsize;

	virtio_cwrite(vps->vdev, struct virtio_pstore_config, bufsize,
		     &bufsize);
}

static int virtpstore_probe(struct virtio_device *vdev)
{
	struct virtio_pstore *vps;
	int err;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "driver init: config access disabled\n");
		return -EINVAL;
	}

	vdev->priv = vps = kzalloc(sizeof(*vps), GFP_KERNEL);
	if (!vps) {
		err = -ENOMEM;
		goto out;
	}
	vps->vdev = vdev;

	err = virtpstore_init_vqs(vps);
	if (err < 0)
		goto out_free;

	virtpstore_init_config(vps);

	err = virt_pstore_init(vps);
	if (err)
		goto out_del_vq;

	virtpstore_confirm_config(vps);

	init_waitqueue_head(&vps->acked);

	virtio_device_ready(vdev);

	dev_info(&vdev->dev, "driver init: ok (bufsize = %luK, flags = %x)\n",
		 vps->pstore.bufsize >> 10, vps->pstore.flags);

	return 0;

out_del_vq:
	vdev->config->del_vqs(vdev);
out_free:
	kfree(vps);
out:
	dev_err(&vdev->dev, "driver init: failed with %d\n", err);
	return err;
}

static void virtpstore_remove(struct virtio_device *vdev)
{
	struct virtio_pstore *vps = vdev->priv;

	virt_pstore_exit(vps);

	/* Now we reset the device so we can clean up the queues. */
	vdev->config->reset(vdev);

	vdev->config->del_vqs(vdev);

	kfree(vps);
}

static unsigned int features[] = {
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PSTORE, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_pstore_driver = {
	.driver.name         = KBUILD_MODNAME,
	.driver.owner        = THIS_MODULE,
	.feature_table       = features,
	.feature_table_size  = ARRAY_SIZE(features),
	.id_table            = id_table,
	.probe               = virtpstore_probe,
	.remove              = virtpstore_remove,
};

module_virtio_driver(virtio_pstore_driver);
MODULE_DEVICE_TABLE(virtio, id_table);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Namhyung Kim <namhyung@kernel.org>");
MODULE_DESCRIPTION("Virtio pstore driver");
