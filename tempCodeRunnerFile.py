def  print_pattern(n):
    counter = 0

    for i in range(1,n+1):
        for j in range(i):
            if counter%2==0:
                char = chr(65+counter)
                print(char, end=" ")
            else:
                char = chr(97 + counter)
                print(char, end = " ")
            
            counter = counter +1
        print()

n = int(input())
print_pattern(n)