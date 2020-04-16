## test behaviour in case of invalid input

flags = ['m', 't', 'c']
invalid_inputs = [-1, 0, 'haha', 0.1, "4 2", -45.1, '0-1' ]

def command(flags, host="test.narek.workers.dev"):
    # for esthetics
    COLOR='\033[0;32m'
    NC='\033[0m' # No Color
    cmd = "sudo ./ping %s %s" % (flags, host)
    print("echo -e '%s $ %s %s'" % (COLOR, cmd, NC))
    print(cmd)

for f in flags:
    for inp in invalid_inputs:
        command("-%s %s" % (f, inp))

command("", host="a b")

# test expected behavour
# choosing small inputs to limit output size
valid_inputs = [1,2,3]
#
for inp in valid_inputs:
    command("-m %s -t %s" % (inp,inp))
    command("-c %s -t %s" % (inp,inp))
    command("-c %s" % (inp))
    command("-t %s" % (inp))

command("-t 1", host="0")
command("-t 1", host="0932485723049578")

command("-t 1", host="corp.com")


# same flag may be passed several times and the very last should be taken
command("-m 42 -m 451 -m 0")
command("-c 3 -t 2 -t 1")
command("-c 4444 -c 444 -c 44 -c 4")