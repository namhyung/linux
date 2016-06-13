#ifndef _LINUX_VIRTIO_PSTORE_H
#define _LINUX_VIRTIO_PSTORE_H
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */
#include <linux/types.h>
#include <linux/virtio_types.h>

#define VIRTIO_PSTORE_CMD_NULL   0
#define VIRTIO_PSTORE_CMD_OPEN   1
#define VIRTIO_PSTORE_CMD_READ   2
#define VIRTIO_PSTORE_CMD_WRITE  3
#define VIRTIO_PSTORE_CMD_ERASE  4
#define VIRTIO_PSTORE_CMD_CLOSE  5

#define VIRTIO_PSTORE_TYPE_UNKNOWN  0
#define VIRTIO_PSTORE_TYPE_DMESG    1

#define VIRTIO_PSTORE_FL_COMPRESSED  1

struct virtio_pstore_req {
	__le16		cmd;
	__le16		type;
	__le32		flags;
	__le64		id;
	__le32		count;
	__le32		reserved;
};

struct virtio_pstore_res {
	__le16		cmd;
	__le16		type;
	__le32		ret;
};

struct virtio_pstore_fileinfo {
	__le64		id;
	__le32		count;
	__le16		type;
	__le16		unused;
	__le32		flags;
	__le32		len;
	__le64		time_sec;
	__le32		time_nsec;
	__le32		reserved;
};

struct virtio_pstore_config {
	__le32		bufsize;
};

#endif /* _LINUX_VIRTIO_PSTORE_H */
