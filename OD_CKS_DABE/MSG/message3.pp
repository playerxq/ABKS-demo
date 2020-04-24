
Python 循环语句

本章节将向大家介绍Python的循环语句，程序在一般情况下是按顺序执行的。

编程语言提供了各种控制结构，允许更复杂的执行路径。

循环语句允许我们执行一个语句或语句组多次，下面是在大多数编程语言中的循环语句的一般形式：

Python 提供了 for 循环和 while 循环（在 Python 中没有 do..while 循环）:
循环类型	描述
while 循环	在给定的判断条件为 true 时执行循环体，否则退出循环体。
for 循环	重复执行语句
嵌套循环	你可以在while循环体中嵌套for循环

循环控制语句

循环控制语句可以更改语句执行的顺序。Python支持以下循环控制语句：
控制语句	描述
break 语句	在语句块执行过程中终止循环，并且跳出整个循环
continue 语句	在语句块执行过程中终止当前循环，跳出该次循环，执行下一次循环。
pass 语句	pass是空语句，是为了保持程序结构的完整性。
Python 条件语句
Python While 循环语句
2 篇笔记 写笔记

       Sonnet

      gra***nnet@qq.com
    257

    八皇后问题 （循环递归法）

    #* queen problem with recurison
    BOARD_SIZE = 8

    def under_attack(col, queens):
       left = right = col
       for r, c in reversed(queens):
     #左右有冲突的位置的列号
           left, right = left - 1, right + 1

           if c in (left, col, right):
               return True
       return False

    def solve(n):
       if n == 0:
           return [[]]

       smaller_solutions = solve(n - 1)

       return [solution+[(n,i+1)]
           for i in xrange(BOARD_SIZE)
               for solution in smaller_solutions
                   if not under_attack(i+1, solution)]
    for answer in solve(BOARD_SIZE):
       print answer

    Sonnet

       Sonnet

      gra***nnet@qq.com
    2年前 (2018-07-17)

       琳琅月

      z46***0448@gmail.com
    149

    实例:

    def deduplication(self, nums):#找出排序数组的索引
        for i in range(len(nums)):
            if nums[i]==self:
                return i
        i=0
        for x in nums:
            if self>x:
                i+=1
        return i
    print(deduplication(5, [1,3,5,6]))

    琳琅月

       琳琅月

      z46***0448@gmail.com
    9个月前 (07-13)
