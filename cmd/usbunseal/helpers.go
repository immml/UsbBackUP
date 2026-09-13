package main

import "context"

// osCtx 返回未附加取消信号的上下文，供单次命令行操作使用。
func osCtx() context.Context { return context.Background() }
