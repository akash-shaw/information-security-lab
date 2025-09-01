def vignere_encrypt(str,key):
    n=len(key)
    j=0
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-65+ord(key[j%n])-97)%26+65)
            j=j+1
        elif str[i].islower():
            ans+=chr((ord(str[i])-97+ord(key[j%n])-97)%26+65)
            j=j+1
        else:
            ans+=str[i]
    return ans

def vignere_decrypt(str,key):
    n=len(key)
    j=0
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-65-ord(key[j%n])+97)%26+97)
            j=j+1
        elif str[i].islower():
            ans+=chr((ord(str[i])-97-ord(key[j%n])+97)%26+97)
            j=j+1
        else:
            ans+=str[i]
    return ans

def autokey_encrypt(str,key):
    ans=""
    for i in range(len(str)):
        if (i==0):
            if str[i].isupper():
                ans+=chr((ord(str[i])+key-65)%26+65)
            elif str[i].islower():
                ans+=chr((ord(str[i])-97+key)%26+65)
            continue
        if str[i].isspace():
            continue
        if str[i].isupper():
            if str[i-1].isupper():
                ans+=chr((ord(str[i])-65+ord(str[i-1])-65)%26+65)
            if str[i-1].islower():
                ans+=chr((ord(str[i])-65+ord(str[i-1])-97)%26+65)
        elif str[i].islower():
            if str[i-1].isupper():
                ans+=chr((ord(str[i])-97+ord(str[i-1])-65)%26+65)
            if str[i-1].islower():
                ans+=chr((ord(str[i])-97+ord(str[i-1])-97)%26+65)
        else:
            ans+=str[i]
    return ans

def autokey_decrypt(str,key):
    x=0
    temp=0
    ans=""
    for i in range(len(str)):
        if (i==0):
            if str[i].isupper():
                x=((ord(str[i])-key-65)%26)
                ans+=chr(x+97)
            elif str[i].islower():
                x=((ord(str[i])-97-key)%26)
                ans+=chr(x+97)
            continue
        if str[i].isspace():
            continue
        if str[i].isupper():
            if str[i-1].isupper():
                temp=((ord(str[i])-65-x)%26)
                x=temp
                ans+=chr(x+97)
            if str[i-1].islower():
                temp=((ord(str[i])-65-x)%26)
                x=temp
                ans+=chr(x+97)
        elif str[i].islower():
            if str[i-1].isupper():
                temp=chr((ord(str[i])-97-x)%26)
                x=temp
                ans+=chr(x+97)
            if str[i-1].islower():
                temp=chr((ord(str[i])-97-x)%26)
                x=temp
                ans+=chr(x+97)
        else:
            ans+=str[i]
    return ans

str=input("Enter the message: ")
key="dollars"
res=vignere_encrypt(str,key)
print(res)