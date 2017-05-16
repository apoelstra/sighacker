
BINNAME=./sighacker

## Check whether a command executes in valgrind without trouble
function valgrind_check {
    valgrind --error-exitcode=-1 $@ >/dev/null 2>&1
    if [ "$?" == "-1" ]
    then
        echo "Valgrind failed on command « $@ »"
        exit 1
    fi
}

## Check whether a function executes and returns success
function success_check {
    valgrind_check $@
    if $@ >/dev/null 2>&1
    then
        sleep 0
    else
        echo "Command « $@ » unexpectedly failed"
        exit 1
    fi
}

## Check whether a function executes and returns failure
function failure_check {
    valgrind_check $@
    if $@ >/dev/null 2>&1
    then
        echo "Command « $@ » unexpectedly succeeded"
        exit 1
    fi
}


## Check whether a function executes and returns success

SK_SHORT=$(head -c 31 /dev/urandom | xxd -p -c 250)
SK_LONG=$(head -c 33 /dev/urandom | xxd -p -c 250)

SK=$(head -c 32 /dev/urandom | xxd -p -c 250)
MSG32=$(head -c 32 /dev/urandom | xxd -p -c 250)
MSG_LONG=$(head -c 125 /dev/urandom | xxd -p -c 250)

failure_check $BINNAME
failure_check $BINNAME uetahsuathsthnahsua
failure_check $BINNAME publickey
success_check $BINNAME publickey $SK
success_check $BINNAME publickey $SK trailing garbage

failure_check $BINNAME sign
failure_check $BINNAME sign $SK_LONG
failure_check $BINNAME sign $SK_SHORT $MSG32
failure_check $BINNAME sign $SK_LONG $MSG32
failure_check $BINNAME sign "-" $MSG32
success_check $BINNAME sign $SK "-"
success_check $BINNAME sign $SK "not hex"
success_check $BINNAME sign $SK $MSG32
success_check $BINNAME sign $SK $MSG_LONG
success_check $BINNAME sign $SK $MSG32 trailing garbage

SIG1=$($BINNAME sign $SK $MSG32 2>/dev/null)
SIG2=$($BINNAME sign $SK $MSG_LONG 2>/dev/null)

if [ "$SIG1" == "$SIG2" ]
then
    echo "Signature of $MSG32 and of $MSG_LONG were equal (sk $SK)"
    exit 1
fi

failure_check $BINNAME publickey
failure_check $BINNAME publickey $SK_SHORT
failure_check $BINNAME publickey $SK_LONG
success_check $BINNAME publickey $SK

PK1=$($BINNAME publickey $SK 2>/dev/null)
PK2=$($BINNAME publickey $SK 2>/dev/null)

if [ "$PK1" != "$PK2" ]
then
    echo "Public key from $SK was not generated consistently"
    exit 1
fi

failure_check $BINNAME verify
failure_check $BINNAME verify $PK1
failure_check $BINNAME verify $PK1 $SIG1
success_check $BINNAME verify $PK1 $SIG1 $MSG32
failure_check $BINNAME verify $PK1 $SIG1 $MSG_LONG
failure_check $BINNAME verify $PK1 $SIG2
failure_check $BINNAME verify $PK1 $SIG2 $MSG32
success_check $BINNAME verify $PK1 $SIG2 $MSG_LONG
failure_check $BINNAME verify $PK1 $SIG2 "not hex"

failure_check $BINNAME verify $PK1 $SIG2$SIG2 $MSG_LONG  ##sig too long
failure_check $BINNAME verify $PK1$PK1 $SIG2 $MSG_LONG   ##pk too long
failure_check $BINNAME verify "-" $SIG2 $MSG_LONG
failure_check $BINNAME verify $PK1 "-" $MSG_LONG

failure_check $BINNAME signtocontract
failure_check $BINNAME signtocontract $SK_LONG
failure_check $BINNAME signtocontract $SK_SHORT
failure_check $BINNAME signtocontract $SK
failure_check $BINNAME signtocontract $SK $MSG_LONG
success_check $BINNAME signtocontract $SK $MSG_LONG $MSG_LONG
failure_check $BINNAME signtocontract $SK "not hex" $MSG_LONG

