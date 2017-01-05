if BUILD_MINIUPNP_ASYNC

lib_LTLIBRARIES +=  libtoxupnp.la
                    libtoxupnp_la_include_HEADERS = ../toxupnp/toxupnp.h
                    libtoxupnp_la_includedir = $(includedir)/tox

libtoxupnp_la_SOURCES = ../toxupnp/toxupnp.h \
                    ../toxupnp/toxupnp.c

libtoxupnp_la_CFLAGS = -I$(top_srcdir)/toxcore \
                    -I$(top_srcdir)/toxupnp \
                    $(MINIUPNP_CFLAGS) \
                    $(PTHREAD_CFLAGS)

libtoxupnp_la_LDFLAGS = $(MINIUPNP_LDFLAGS) \
                    $(EXTRA_LT_LDFLAGS)

libtoxupnp_la_LIBADD = $(MINIUPNP_LIBS) \
                    $(PTHREAD_LIBS)

endif
