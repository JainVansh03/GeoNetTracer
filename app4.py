class hello:
    def  printpattern(self,n):
     counter = 0

     for i in range(1,n+1):
        for j in range(i):
            if counter%2==0:
                char = chr(65+counter)
                return(char, end=" ")
            else:
                char = chr(97 + counter)
                return(char, end = " ")
            
            counter = counter +1
        print()
'''print("Enter the number")'''
n = int(input())
a = hello()
print(a.printpattern(n))