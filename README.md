# tstoapkpatcher

## How to use

The prerequisite is that docker is installed and running correctly.

### docker

Create a folder, open a prompt in it, run the command (replace variables where applicable e.g. IP addresses to correct values): 

`docker run -e APK_FILE="/apk/test.apk" -e SOURCE_OUTPUT=/apk/decompiled -e GAMESERVER_URL=http://1.2.3.4:9000 -e DIRECTOR_URL=http://1.2.3.4:9000 -e DLC_URL=http://1.2.3.4:9000/gameassets/ -v ./:/apk ghcr.io/d-fens/tstoapkpatcher:main`

### docker compose

Download the [docker-compose.yml](https://raw.githubusercontent.com/d-fens/tstoapkpatcher/refs/heads/main/docker-compose.yml) file into an **empty** directory. 

Edit the APK name as required in the `docker-compose.yml` file while noting that the `/apk` prefix on the start is required due to the volume mount for now.

Run `docker compose run patcher` in a command prompt in the same folder.

### Troubleshooting

Provide hashes for `.so` files and output from container which can be obtained using `docker compose logs` and if possible the emulator or device type.
