## Building a Dshell Docker image

Step 1: Build a Docker image that has Dshell installed and configured
```bash
sudo docker build -t dshell .
```

Step 2: Run the container with a native host directory (/home/user/pcap/) mounted in /mnt/pcap
```bash
sudo docker run -v /home/user/pcap:/mnt/pcap -it dshell
```

Step 3: Use Dshell to analyze network traffic
```bash
decode -d netflow /mnt/pcap/*.pcap
```
