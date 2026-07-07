# Regenerate docs/demo.gif. Prereqs: `warden-demo` image built
# (docker build -f demo/gif/Dockerfile -t warden-demo .) and the compose stack
# up (postgres + `--profile gate` rekor-server). Then, from the repo root:
#   vhs demo/gif/demo.tape
#   gifsicle -O3 --lossy=80 --colors 32 docs/demo.gif -o docs/demo.gif   # ~5.5M -> ~1.7M
Output docs/demo.gif
Require docker

Set Shell "bash"
Set FontSize 13
Set Width 960
Set Height 640
Set Padding 20
Set Framerate 10

Hide
Type "clear"
Enter
Show

Type "./demo/gif/play.sh"
Sleep 400ms
Enter
Sleep 13s
Sleep 2000ms
