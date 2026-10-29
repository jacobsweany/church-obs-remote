#!/bin/zsh
# Remote screenshot helper: runs screencapture inside Terminal.app, which
# holds the Screen Recording TCC permission (the dashboard's Python and
# sshd do not). Terminal window opens briefly and closes itself.
OUT="${1:-/tmp/zoom_shot.png}"
osascript <<OSA
tell application "Terminal"
    set newWin to do script "screencapture -x '$OUT'"
    delay 4
    try
        close newWin
    end try
end tell
OSA
