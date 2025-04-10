package utils

import (
	"fmt"
	"sync"
)

var (
	SocksList     []string
	EffectiveList []string
	proxyIndex    int
	Timeout       int
	LastDataFile  = "lastData.txt"
	Wg            sync.WaitGroup
	Mu            sync.Mutex // 导出 Mu
	semaphore     chan struct{}
)

// 导出 AddSocksMu 以在其他包中使用
var AddSocksMu sync.Mutex

func Banner() {
	banner := `
   ____                        __                          ___      
  /\ $_$\                     /\ \                        /\_ \     
  \ \ \/\ \     __     __     \_\ \  _____     ___     ___\//\ \    
   \ \ \ \ \  /@__@\ /^__^\   />_< \/\ -__-\  /*__*\  /'__'\\ \ \   
    \ \ \_\ \/\  __//\ \_\.\_/\ \-\ \ \ \_\ \/\ \-\ \/\ \_\ \\-\ \_ 
     \ \____/\ \____\ \__/.\_\ \___,_\ \ ,__/\ \____/\ \____//\____\
      \/___/  \/____/\/__/\/_/\/__,_ /\ \ \/  \/___/  \/___/ \/____/
                                       \ \_\                        
                                        \/_/                        
`
	fmt.Println(banner)
}
