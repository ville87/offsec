# All Stuff JS
## Debugging
To list all currently loaded JavaScript variables in the browsers console:   
```
for(var b in window) {
if(window.hasOwnProperty(b)) console.log(b);
}
```
Another method with more output:   
```
var n, arg, name;
console.log("typeof this = " + typeof this);
for (name in this) {
    console.log("this[" + name + "]=" + this[name]);
}
for (n = 0; n < arguments.length; ++n) {
    arg = arguments[n];
    console.log("typeof arguments[" + n + "] = " + typeof arg);
    for (name in arg) {
        console.log("arguments[" + n + "][" + name + "]=" + arg[name]);
    }
}
``` 

## Searching for low hanging fruits
### Secretfinder
`$ for url in $(cat /root/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -o cli; done`   
Using a proxy:   
`$ for url in $(cat /home/kali/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -p http://localhost:8080 -o cli; done`    

### Linkfinder
`# for url in $(cat /root/Desktop/urls_js.txt); do python3 linkfinder.py -i $url -o cli; done`   
