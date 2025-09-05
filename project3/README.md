```
package main

import "fmt"

func main() {
    cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }
    cnp <- func() {
        fmt.Println("HERE1")
    }
    fmt.Println("Hello")
}

```

## Explain what the following code is attempting to do ?
- We are creating a go channel of capacity 10 of type func, channels are used in go for inter thread communications
- Then we are creating 4 parrallel threads, which loops through the channel indefinitely and run the functions in the channel
- Then we are sending a function in the channel.
- The "HERE1" is not printed, because the main thread gets exited, before any of the created threads execute the function, as the main thread exits all other threads exits.
- If create a delay we can see the "HERE1"



```
package main

import (
	"fmt"
	"time"
)

func main() {
	cnp := make(chan func(), 10)
	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
			}
		}()
	}
	cnp <- func() {
		fmt.Println("HERE1")
	}
	fmt.Println("Hello")
	time.Sleep(2 * time.Second)

}
```