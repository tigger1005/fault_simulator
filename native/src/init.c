#include <sentry.h>

void init_native(void) {
  sentry_options_t *options = sentry_options_new();
  sentry_options_set_dsn(options, "__SENTRY_DSN__");
  sentry_options_set_debug(options, 1);
  sentry_options_set_handler_path(options, "crashpad_handler");
  sentry_init(options);
}
