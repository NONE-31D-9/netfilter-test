all: netfilter-test
	g++ -o netfilter-test nfqnl_test.c netfilter-test.o -lnetfilter_queue

netfilter-test:
	g++ -c -o netfilter-test.o netfilter-test.cpp 

clean:
	rm -rf netfilter-test *.o