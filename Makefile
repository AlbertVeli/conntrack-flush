OBJS = conntrack-flush.o

LIBS = -lnetfilter_conntrack -lnfnetlink -lmnl

conntrack-flush: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

.PHONY: clean

clean:
	rm -f conntrack-flush $(OBJS)
