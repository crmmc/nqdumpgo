import subprocess
import json
import os
import glob
allarch = json.loads(subprocess.getoutput("go tool dist list -json"))
print("Building release files for all system")
for i in allarch:
    GOARCH = i['GOARCH']
    GOOS = i['GOOS']
    print("NOW Building: {}/{}".format(GOARCH, GOOS))
    print(subprocess.run(
        'set CGO_ENABLED=0&&set GOARCH={}&&set GOOS={}&&go build -o nqdumpgo_{}_{} -ldflags="-w -s"'.format(GOARCH, GOOS, GOARCH, GOOS), shell=True).returncode)
print("USING UPX TO COMPRESS BINARY FILES")
for i2 in glob.glob("nqdumpgo_*"):
    os.system("upx --best " + i2)
print("Done!")
