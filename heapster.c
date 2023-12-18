#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>    
#include <unistd.h>  
#include <errno.h>
#include <ctype.h>


#define MAX_ALLOC_SIZE (64000) 
#define MAX_DELAY (1000 * 1000) 
#define MAX_ALLOCATIONS 100 


int num_leaks = 0;

// Le buckets for libmalloc
void print_zone(size_t size) {
    char *nanoZone = getenv("MallocNanoZone"); 

    if (nanoZone == NULL || strcmp(nanoZone, "0") != 0) {
        if (size <= 256) {
            printf("Zone: Nano\n");
            return; 
        }
    }

    if (size <= 1008) {
        printf("Zone: Tiny\n");
    } else if (size <= 32 * 1024) {
        printf("Zone: Small\n");
    } else if (size <= 8192 * 1024) {
        printf("Zone: Medium\n");
    } else {
        printf("Zone: Large\n");
    }
}


void flag(){
    printf("You found the flag!\n");
}


void print_usage() {
    printf("Commands:\n");
    printf("  free [address]\n");
    printf("  malloc [size] [num_allocations]\n");
    printf("  uw [size] [address] - uncontrolled write\n");
    printf("  execute - executes last freed address\n");
    printf("  cw [where_hex_address] [what_hex_value] - controlled write\n");
    printf("  spray [size] [address] [number of allocations] - heap spray an address as the payload\n");
    printf("  request [request_number] - similar to a leaky service :D \n");
    printf("  show_leaks - show if you have any memory leaks\n");
    printf("  dump - dump (print) the contents of an address\n");
    printf("  exit\n");
}


void handle_request(int request_id, void **leak_bucket) {
    size_t session_data_size = 128 + sizeof(void (*)());  
    void *session_data = malloc(session_data_size); 
    void (**flag_ptr_in_session)() = (void (**)())(session_data + 128); 
    *flag_ptr_in_session = flag;

    printf("Handling request %d, session data at %p\n", request_id, session_data);
    // Simulate conditions where memory is not freed.
    if (request_id % 5 == 0) {
        printf("Memory leak simulated, data for request %d not freed!\n", request_id);
        leak_bucket[request_id / 5] = session_data;  
        //printf("Stored leak at index %d with address %p\n", request_id / 5, session_data);
        num_leaks++;
    } else {
        free(session_data);  
    }
}

int main(int argc, char *argv[]) {
    int showFlagAddress = 0;
    int randomize_allocations = 0;
    size_t heap_size = 0;
    srand(time(NULL));

    if (argc == 4) {
        if (strcmp(argv[3], "--show-flag") == 0) {
            showFlagAddress = 1;
        }
    } else if (argc != 3) {
        printf("Usage: ./heaptester bytes_of_heap_allocated number_of_allocations\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--randomize") == 0) {
            randomize_allocations = 1;
        } else if (i == 1) { // First positional argument for heap size
            heap_size = strtoul(argv[i], NULL, 10);
            if (heap_size == 0 && errno == EINVAL) {
                fprintf(stderr, "Invalid heap size.\n");
                return 1;
            }
        }
    }

    if (showFlagAddress) {
        printf("Address of flag function: %p\n", flag);
    }

    void *last_allocated = NULL;
    void *last_freed = NULL;
    void *leak_bucket[10];
    memset(leak_bucket, 0, sizeof(leak_bucket));

    size_t size = atoi(argv[1]);
    int num_allocations = atoi(argv[2]);
    void **pointers = malloc(num_allocations * sizeof(void *));

    // overwrite the number of allocations if randomize is choosen
    if (randomize_allocations) {
        num_allocations = rand() % MAX_ALLOCATIONS + 1;
        printf("Randomized number of allocations: %d\n", num_allocations);
    } 

    for (int i = 0; i < num_allocations; ++i) {
        if (randomize_allocations){
            size = (rand() % MAX_ALLOC_SIZE) + 1;
        }
        pointers[i] = malloc(size);
        printf("Allocated at %p ", pointers[i]);
        print_zone(size);
        last_allocated = (void *)pointers[i];
    }


    char line[256];

    while (1) {
        printf("Enter command: ");
        fgets(line, sizeof(line), stdin);

        char *cmd = strtok(line, " \n");

        if (cmd == NULL) {
            print_usage();
            continue;
        }

        if (strcmp(cmd, "free") == 0) {
            char *arg1 = strtok(NULL, " \n");
            if (arg1) {
                unsigned long addr = strtoul(arg1, NULL, 16);

                // If you love something set it free
               free((void *)addr);
               last_freed = (void *)addr;
               printf("Freed 0x%lx\n", addr);
                
            } else {
                print_usage();
            }
        } else if (strcmp(cmd, "malloc") == 0) {
            char *arg1 = strtok(NULL, " \n");
            char *arg2 = strtok(NULL, " \n");
            if (arg1 && arg2) {
                size_t new_size = atoi(arg1);
                int new_num_allocations = atoi(arg2);
                for (int i = 0; i < new_num_allocations; ++i) {
                    void *new_ptr = malloc(new_size);
                    printf("Allocated at %p ", new_ptr);
                    print_zone(new_size);
                    last_allocated = (void *)new_ptr;
                }
            } else {
                print_usage();
            }
        } else if (strcmp(cmd, "uw") == 0) { 
            char *arg1 = strtok(NULL, " \n");
            char *arg2 = strtok(NULL, " \n");
            if (arg1 && arg2){
                size_t uw_size = atoi(arg1);
                unsigned long user_addr = strtoul(arg2, NULL, 16);

                // But if it comes back, it was meant to be.
                void *uw_ptr = malloc(uw_size);  
                *((size_t *)uw_ptr) = user_addr;
                last_allocated = (void *)uw_ptr;
                printf("Wrote the user-provided address 0x%lx into allocated block at %p\n", user_addr, uw_ptr);
                
            } else {
                print_usage();
            }    
        
        } else if (strcmp(cmd, "spray") == 0) {
            //eat, spray, love...
            char *arg1 = strtok(NULL, " \n"); // size
            char *arg2 = strtok(NULL, " \n"); // address to spray
            char *arg3 = strtok(NULL, " \n"); // number of allocations
            if (arg1 && arg2 && arg3) {
                size_t spray_size = atoi(arg1);
                unsigned long spray_address = strtoul(arg2, NULL, 16);
                int spray_allocations = atoi(arg3);

                for (int i = 0; i < spray_allocations; ++i) {
                    void *spray_ptr = malloc(spray_size);
                    if (spray_ptr) {
                        memset(spray_ptr, 0, spray_size);
                        *(unsigned long *)spray_ptr = spray_address;
                        printf("Sprayed 0x%lx to %p\n", spray_address, spray_ptr);
                    }
                }
            } else {
                print_usage();
            }
	    } else if (strcmp(cmd, "execute") == 0) {
            printf("Attempting to execute last freed address %p\n", last_freed);
            void (*func_ptr)() = *((void (**)())(last_freed));
            // Execute or die
            func_ptr(); 
        } else if (strcmp(cmd, "request") == 0) {
            
            char *arg1 = strtok(NULL, " \n");
            if (arg1) {
                int request_id = atoi(arg1);
                // Simulate a request
                handle_request(request_id, leak_bucket); 
            } else {
                print_usage();
            }
        } else if (strcmp(cmd, "show_leaks") == 0) {
            
            for (int i = 0; i < num_leaks; ++i) {
                void *leaked_block = leak_bucket[i + 1];  
                if (leaked_block != NULL) {
                    printf("Leaked block at %p\n", leaked_block);
                    // get and show the flag address
                    void (*leaked_flag_ptr)() = *((void (**)())(leaked_block + 128));  
                    printf("Hmmmm: %p\n", leaked_flag_ptr);
                } else {
                    printf("Leaked block is NULL\n");
                }

            }
        } else if (strcmp(cmd, "cw") == 0) {
            //why not
            char *arg1 = strtok(NULL, " \n");
            char *arg2 = strtok(NULL, " \n");
            if (arg1 && arg2) {
                unsigned long where = strtoul(arg1, NULL, 16);
                unsigned long what = strtoul(arg2, NULL, 16);

                // Write 'what' to 'where'
                *(unsigned long *)where = what;
                printf("Written 0x%lx to 0x%lx\n", what, where);
           
            } else {
            printf("Usage: cw [where_hex_address] [what_hex_value]\n");
            }

        } else if (strcmp(cmd, "dump") == 0) {
            char *arg1 = strtok(NULL, " \n"); 
            char *arg2 = strtok(NULL, " \n"); 
            if (arg1 && arg2) {
                unsigned long addr = strtoul(arg1, NULL, 16);
                int length = atoi(arg2);

                unsigned char *ptr = (unsigned char *)addr;
                printf("Dumping memory at address 0x%lx:\n", addr);
                for (int i = 0; i < length; i++) {
                    if (i % 16 == 0) {
                        if (i != 0) {
                            printf(" | "); 
                            for (int j = i - 16; j < i; j++) { 
                                printf("\x1B[36m%c\x1B[0m", isprint(ptr[j]) ? ptr[j] : '.');
                            }
                            printf("\n"); 
                        }
                        printf("0x%lX ", addr + i); 
                    }
                    printf("\x1B[32m%02X \x1B[0m", ptr[i]); 
                    if (i == length - 1) {
                        int remaining = 16 - (length % 16);
                        if (remaining != 16) {
                            printf(" ");
                            for (int j = 0; j < remaining; j++) {
                                printf("   ");
                            }
                        }
 
                        printf(" | "); 
                        int start = i - (i % 16);
                        for (int j = start; j <= i; j++) { 
                            printf("\x1B[36m%c\x1B[0m", isprint(ptr[j]) ? ptr[j] : '.');
                        }
                        printf("\n");
                    }
                 }
            } else {
                print_usage();
            }
        } else if (strcmp(cmd, "exit") == 0) {
            break;
        } else {
            print_usage();
        }
    }

    // let's be nice, will cause aborts on freed but non-absorbed memory
    for (int i = 0; i < num_allocations; ++i) {
        if (pointers[i] != NULL) {
            free(pointers[i]);
        }
    }
    free(pointers);
    return 0;
}

