# All Stuff JS
## Searching for low hanging fruits
### Secretfinder
`$ for url in $(cat /root/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -o cli; done`   
Using a proxy:   
`$ for url in $(cat /home/kali/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -p http://localhost:8080 -o cli; done`    

### Linkfinder
`# for url in $(cat /root/Desktop/urls_js.txt); do python3 linkfinder.py -i $url -o cli; done`   
