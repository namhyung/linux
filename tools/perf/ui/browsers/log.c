#include <stdio.h>

#include "perf.h"
#include "util/util.h"
#include "util/cache.h"
#include "util/debug.h"
#include "ui/ui.h"
#include "ui/util.h"
#include "ui/browser.h"
#include "ui/libslang.h"
#include "ui/keysyms.h"

struct log_browser_data {
	unsigned long offset;
	u32 alloc;
	char filter[64];
};

static void __log_menu__filter(struct ui_browser *menu, char *filter);

static void ui_browser__file_seek(struct ui_browser *browser __maybe_unused,
				  off_t offset __maybe_unused,
				  int whence __maybe_unused)
{
	/* do nothing */
}

static void ui_browser__file_write(struct ui_browser *browser,
				   void *entry, int row)
{
	char buf[1024];
	char empty[] = " ";
	FILE *fp = perf_log.fp;
	struct log_browser_data *lbd = browser->priv;
	bool current_entry = ui_browser__is_current_entry(browser, row);
	off_t *linemap = browser->entries;
	unsigned int idx = *(unsigned int *)entry;
	unsigned long offset = lbd->offset;

	fseek(fp, linemap[idx], SEEK_SET);
	if (fgets(buf, sizeof(buf), fp) == NULL)
		return;

	ui_browser__set_color(browser, current_entry ? HE_COLORSET_SELECTED :
						       HE_COLORSET_NORMAL);

	if (offset < strlen(buf))
		slsmg_write_nstring(&buf[offset], browser->width);
	else
		slsmg_write_nstring(empty, browser->width);
}

static unsigned int ui_browser__file_refresh(struct ui_browser *browser)
{
	unsigned int row = 0;
	unsigned int idx = browser->top_idx;
	struct log_browser_data *lbd = browser->priv;
	fpos_t pos;

	fgetpos(perf_log.fp, &pos);

	if (perf_log.linemap_changed) {
		/* update log window with new linemap */
		__log_menu__filter(browser, lbd->filter);
		perf_log.linemap_changed = false;
	}

	while (idx < browser->nr_entries) {
		ui_browser__gotorc(browser, row, 0);
		browser->write(browser, &idx, row);
		if (++row == browser->height)
			break;

		++idx;
	}

	fsetpos(perf_log.fp, &pos);
	return row;
}

static void __log_menu__filter(struct ui_browser *menu, char *filter)
{
	char buf[1024];
	struct log_browser_data *lbd = menu->priv;
	off_t *linemap = NULL;
	u32 lines = 0;
	u32 alloc = 0;
	u32 i;

	if (*filter == '\0') {
		linemap = perf_log.linemap;
		lines = perf_log.lines;
		goto out;
	}

	for (i = 0; i < perf_log.lines; i++) {
		fseek(perf_log.fp, perf_log.linemap[i], SEEK_SET);
		if (fgets(buf, sizeof(buf), perf_log.fp) == NULL)
			goto error;

		if (strstr(buf, filter) == NULL)
			continue;

		if (lines == alloc) {
			off_t *map;

			map = realloc(linemap, (alloc + 128) * sizeof(*map));
			if (map == NULL)
				goto error;

			linemap = map;
			alloc += 128;
		}

		linemap[lines++] = perf_log.linemap[i];
	}

out:
	if (lbd->alloc) {
		BUG_ON(menu->entries == perf_log.linemap);
		free(menu->entries);
	}
	lbd->alloc = alloc;

	menu->entries = linemap;
	ui_browser__update_nr_entries(menu, lines);
	return;

error:
	free(linemap);
}

static void log_menu__filter(struct ui_browser *menu, char *filter)
{
	fpos_t pos;

	pthread_mutex_lock(&ui__lock);
	fgetpos(perf_log.fp, &pos);
	__log_menu__filter(menu, filter);
	fsetpos(perf_log.fp, &pos);
	perf_log.linemap_changed = false;
	pthread_mutex_unlock(&ui__lock);
}

static int log_menu__run(struct ui_browser *menu)
{
	int key;
	struct log_browser_data *lbd = menu->priv;
	const char help[] =
	"h/?/F1        Show this window\n"
	"UP/DOWN/PGUP\n"
	"PGDN/SPACE\n"
	"LEFT/RIGHT    Navigate\n"
	"q/ESC/CTRL+C  Exit browser\n\n"
	"/             Filter log message";

	if (ui_browser__show(menu, "Log messages", "Press 'q' to exit") < 0)
		return -1;

	while (1) {
		key = ui_browser__run(menu, 0);

		switch (key) {
		case K_RIGHT:
			lbd->offset += 10;
			continue;
		case K_LEFT:
			if (lbd->offset >= 10)
				lbd->offset -= 10;
			continue;
		case K_F1:
		case 'h':
		case '?':
			ui_browser__help_window(menu, help);
			continue;
		case '/':
			if (ui_browser__input_window("Symbol to filter",
					"Please enter the name of symbol you want to see",
					lbd->filter, "ENTER: OK, ESC: Cancel",
					0) == K_ENTER) {
				log_menu__filter(menu, lbd->filter);
			}
			continue;
		case K_ESC:
		case 'q':
		case CTRL('c'):
			key = -1;
			break;
		default:
			continue;
		}

		break;
	}

	ui_browser__hide(menu);
	return key;
}

int tui__log_window(void)
{
	struct log_browser_data lbd = {
		.filter	    = "",
	};
	struct ui_browser log_menu = {
		.refresh    = ui_browser__file_refresh,
		.seek	    = ui_browser__file_seek,
		.write	    = ui_browser__file_write,
		.entries    = perf_log.linemap,
		.nr_entries = perf_log.lines,
		.priv	    = &lbd,
	};
	int key;

	key = log_menu__run(&log_menu);

	if (lbd.alloc)
		free(log_menu.entries);

	return key;
}
