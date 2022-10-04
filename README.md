# elfhook
程序对某个so文件实现了hook，使用到的都是ELF文件结构的基础知识，例如文件头、节区头、程序头的读取，各个节区各个表内成员的利用，获取so内部函数地址以及外部so导入函数地址，寻找节区指定大小的空白区域，以及shellcode注入的RVA的计算

usage: ./elfhook target.so


