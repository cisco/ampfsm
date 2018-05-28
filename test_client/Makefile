all: test_client

test_client: test_client.c
	$(CC) -o $@ $< -Wall -Wextra -g -lmnl

clean:
	rm -f test_client
