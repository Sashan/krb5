import os
import re

from k5test import *

#
# Solaris Kerberos
#
# We cannot run register iprop rpc program twice on one host and
# hence we are not able to test hierarchical iprop on a single host.
# This test has been modified to test 'flat' iprop only.
#

# On macOS with System Integrity Protection enabled, this script hangs
# in the wait_for_prop() call after starting the first kpropd process,
# most likely due to signal restrictions preventing the listening
# child from informing the parent that a full resync was processed.
if which('csrutil'):
    out = subprocess.check_output(['csrutil', 'status'],
                                  universal_newlines=True)
    if 'status: enabled' in out:
        skip_rest('iprop tests', 'System Integrity Protection is enabled')

# Read lines from kpropd output until we are synchronized.  Error if
# full_expected is true and we didn't see a full propagation or vice
# versa.
def wait_for_prop(kpropd, full_expected, expected_old, expected_new):
    output('*** Waiting for sync from kpropd\n')
    full_seen = sleep_seen = False
    old_sno = new_sno = -1
    while True:
        line = kpropd.stdout.readline()
        if line == '':
            fail('kpropd process exited unexpectedly')
        output('kpropd: ' + line)

        m = re.match(r'Calling iprop_get_updates_1 \(sno=(\d+) ', line)
        if m:
            if not full_seen:
                old_sno = int(m.group(1))
            # Also record this as the new sno, in case we get back
            # UPDATE_NIL.
            new_sno = int(m.group(1))

        m = re.match(r'Got incremental updates \(sno=(\d+) ', line)
        if m:
            new_sno = int(m.group(1))

        if 'KDC is synchronized' in line or 'Incremental updates:' in line:
            break

        # After a full resync request, these lines could appear in
        # either order.
        if 'Waiting for' in line:
            sleep_seen = True
        if 'load process for full propagation completed' in line:
            full_seen = True

        # Detect some failure conditions.
        if 'Still waiting for full resync' in line:
            fail('kadmind gave consecutive full resyncs')
        if 'Rejected connection' in line:
            fail('kpropd rejected kprop connection')
        if 'get updates failed' in line:
            fail('iprop_get_updates failed')
        if 'permission denied' in line:
            fail('kadmind denied update')
        if 'error from master' in line or 'error returned from master' in line:
            fail('kadmind reported error')
        if 'invalid return' in line:
            fail('kadmind returned invalid result')

    if full_expected and not full_seen:
        fail('Expected full dump but saw only incremental')
    if full_seen and not full_expected:
        fail('Expected incremental prop but saw full dump')
    if old_sno != expected_old:
         fail('Expected old serial %d from kpropd sync' % expected_old)
    if new_sno != expected_new:
         fail('Expected new serial %d from kpropd sync' % expected_new)

    # Wait until kpropd is sleeping before continuing, to avoid races.
    # (This is imperfect since there's there is a short window between
    # the fprintf and the sleep; kpropd will need design changes to
    # fix that.)
    while True:
        line = kpropd.stdout.readline()
        output('kpropd: ' + line)
        if 'Waiting for' in line:
            break
    output('*** Sync complete\n')

# Verify the output of kproplog against the expected number of
# entries, first and last serial number, and a list of principal names
# for the update entrires.
def check_ulog(num, first, last, entries, env=None):
    out = realm.run([kproplog], env=env)
    if 'Number of entries : ' + str(num) + '\n' not in out:
        fail('Expected %d entries' % num)
    if last:
        firststr = first and str(first) or 'None'
        if 'First serial # : ' + firststr + '\n' not in out:
            fail('Expected first serial number %d' % first)
    laststr = last and str(last) or 'None'
    if 'Last serial # : ' + laststr + '\n' not in out:
        fail('Expected last serial number %d' % last)
    assert(len(entries) == num)
    ser = first - 1
    entindex = 0
    for line in out.splitlines():
        m = re.match(r'\tUpdate serial # : (\d+)$', line)
        if m:
            ser = ser + 1
            if m.group(1) != str(ser):
                fail('Expected serial number %d in update entry' % ser)
        m = re.match(r'\tUpdate principal : (.*)$', line)
        if m:
            eprinc = entries[ser - first]
            if eprinc == None:
                fail('Expected dummy update entry %d' % ser)
            elif m.group(1) != eprinc:
                fail('Expected princ %s in update entry %d' % (eprinc, ser))
        if line == '\tDummy entry':
            eprinc = entries[ser - first]
            if eprinc != None:
                fail('Expected princ %s in update entry %d' % (eprinc, ser))

# replica1 will receive updates from master, and replica2 will receive
# updates from replica1.  Because of the awkward way iprop and kprop
# port configuration currently works, we need separate config files
# for the replica and master sides of replica1, but they use the same
# DB and ulog file.
conf = {'realms': {'$realm': {'iprop_enable': 'true',
                              'iprop_logfile': '$testdir/db.ulog'}}}
conf_rep1 = {'realms': {'$realm': {'iprop_replica_poll': '600',
                                   'iprop_logfile': '$testdir/ulog.replica1'}},
             'dbmodules': {'db': {'database_name': '$testdir/db.replica1'}}}

for realm in multidb_realms(kdc_conf=conf, create_user=False,
                            start_kadmind=True):
    replica1 = realm.special_env('replica1', True, kdc_conf=conf_rep1)

    # Define some principal names.  pr3 is long enough to cause internal
    # reallocs, but not long enough to grow the basic ulog entry size.
    pr1 = 'wakawaka@' + realm.realm
    pr2 = 'w@' + realm.realm
    c = 'chocolate-flavored-school-bus'
    cs = c + '/'
    pr3 = (cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + c +
           '@' + realm.realm)

    # Create the kpropd ACL file.
    acl_file = os.path.join(realm.testdir, 'kpropd-acl')
    acl = open(acl_file, 'w')
    acl.write(realm.host_princ + '\n')
    acl.close()

    ulog = os.path.join(realm.testdir, 'db.ulog')
    if not os.path.exists(ulog):
        fail('update log not created: ' + ulog)

    # Create the principal used to authenticate kpropd to kadmind.
    kiprop_princ = 'kiprop/' + hostname
    realm.extract_keytab(kiprop_princ, realm.keytab)

    # Create the initial replica databases.
    dumpfile = os.path.join(realm.testdir, 'dump')
    realm.run([kdb5_util, 'dump', dumpfile])
    realm.run([kdb5_util, 'load', dumpfile], replica1)

    # Reinitialize the master ulog so we know exactly what to expect in
    # it.
    realm.run([kproplog, '-R'])
    check_ulog(1, 1, 1, [None])

    # Make some changes to the master DB.
    realm.addprinc(pr1)
    realm.addprinc(pr3)
    realm.addprinc(pr2)
    realm.run([kadminl, 'modprinc', '-allow_tix', pr2])
    realm.run([kadminl, 'modprinc', '+allow_tix', pr2])
    check_ulog(6, 1, 6, [None, pr1, pr3, pr2, pr2, pr2])

    # Start kpropd for replica1 and get a full dump from master.
    mark('propagate M->1 full')
    kpropd1 = realm.start_kpropd(replica1, ['-d'])
    wait_for_prop(kpropd1, True, 1, 6)
    out = realm.run([kadminl, 'listprincs'], env=replica1)
    if pr1 not in out or pr2 not in out or pr3 not in out:
        fail('replica1 does not have all principals from master')
    check_ulog(1, 6, 6, [None], replica1)

    # Make a change and check that it propagates incrementally.
    mark('propagate M->1 incremental')
    realm.run([kadminl, 'modprinc', '-allow_tix', pr2])
    check_ulog(7, 1, 7, [None, pr1, pr3, pr2, pr2, pr2, pr2])
    kpropd1.send_signal(signal.SIGUSR1)
    wait_for_prop(kpropd1, False, 6, 7)
    check_ulog(2, 6, 7, [None, pr2], replica1)
    realm.run([kadminl, 'getprinc', pr2], env=replica1,
              expected_msg='Attributes: DISALLOW_ALL_TIX')

    # Start kadmind -proponly for replica1.  (Use the replica1m
    # environment which defines iprop_port to $port8.)
    replica1_out_dump_path = os.path.join(realm.testdir, 'dump.replica1.out')
success('iprop tests')
