"""Exercise the real installer in a filesystem sandbox with mocked OS services.

No host package manager or systemd command is executed. tar/sha256sum/install
remain real, so archive extraction, integrity checks, file permissions, and
rollback are exercised rather than merely checking shell text.
"""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "public/install.sh"
MOCK = r'''#!/usr/bin/python3
import os,sys,pathlib,shutil
root=pathlib.Path(os.environ['TEST_ROOT']);name=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
with (root/'calls').open('a') as f:f.write(name+' '+' '.join(a)+'\n')
if name=='id':print(0)
elif name=='uname':print('Linux' if a==['-s'] else os.environ.get('TEST_ARCH','x86_64'))
elif name=='systemctl':
 if a[:2]==['is-active','--quiet']:sys.exit(0 if (root/'running').exists() else 1)
 if a and a[0]=='start':(root/'running').touch()
elif name in ['apt-get','dnf','yum']:
 if name=='dnf' and 'fail2ban' in a and os.environ.get('TEST_EPEL')=='1' and not (root/'epel').exists():sys.exit(1)
 if 'epel-release' in a:(root/'epel').touch()
 if 'fail2ban' in a:(root/'mock/fail2ban-client').write_text('#!/bin/sh\nexit 0\n');(root/'mock/fail2ban-client').chmod(0o755)
elif name=='curl':
 if '%{url_effective}' in a:print('https://github.com/cloverstd/fail2ban-mate/releases/tag/v0.1.0')
 else:
  dest=a[a.index('-o')+1];url=a[-3] if a[-2]=='-o' else ''
  shutil.copyfile(root/'downloads'/url.rsplit('/',1)[-1],dest)
'''
BINARY = r'''#!/bin/sh
printf '%s\n' "binary $1" >> "$TEST_ROOT/calls"
case "$1" in
 enroll)
  [ "${TEST_ENROLL_FAIL:-0}" != 1 ] || exit 1
  while [ "$#" -gt 0 ]; do if [ "$1" = --config ]; then shift; printf '%s' '{"token":"test"}' > "$1"; break; fi; shift; done;;
esac
'''

class InstallerTests(unittest.TestCase):
    def run_install(self, distro="apt-get", arch="x86_64", existing=False, tamper=False, fail_enroll=False, epel=False, action=None,ufw=False):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);mock=root/'mock';mock.mkdir();downloads=root/'downloads';downloads.mkdir()
            for path in ['run/systemd/system','etc/systemd/system','etc/fail2ban-mate','var/lib/fail2ban-mate','usr/local/bin','etc/fail2ban/jail.d']:(root/path).mkdir(parents=True,exist_ok=True)
            original=root/'etc/fail2ban/jail.d/original.local';original.write_text('[sshd]\nenabled=true\n')
            for name in ['id','uname','systemctl','curl',distro]:
                p=mock/name;p.write_text(MOCK);p.chmod(0o755)
            if ufw:
                p=mock/'ufw';p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
            if existing:
                p=mock/'fail2ban-client';p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
            target_arch='arm64' if arch=='aarch64' else 'amd64';archive=f'fail2ban-mate-client_linux_{target_arch}.tar.gz'
            with tarfile.open(downloads/archive,'w:gz') as tar:
                info=tarfile.TarInfo('fail2ban-mate-client');b=BINARY.encode();info.size=len(b);info.mode=0o755;tar.addfile(info,io.BytesIO(b))
            digest=hashlib.sha256((downloads/archive).read_bytes()).hexdigest()
            (downloads/'SHA256SUMS').write_text(f'{"0"*64 if tamper else digest}  {archive}\n')
            config=root/'etc/fail2ban-mate/config.json';binary=root/'usr/local/bin/fail2ban-mate-client'
            if action or fail_enroll:
                config.write_text('{"preserved":true}');binary.write_text(BINARY+'\n# previous\n');binary.chmod(0o755);(root/'running').touch()
            script=SOURCE.read_text()
            for p in ['/etc/fail2ban-mate','/var/lib/fail2ban-mate','/usr/local/bin','/etc/systemd/system','/run/systemd/system','/run/fail2ban']:script=script.replace(p,str(root/p.lstrip('/')))
            for tool in ['apt-get','dnf','yum','fail2ban-client']:script=script.replace(f'command -v {tool} >/dev/null 2>&1',f'[ -x "{mock/tool}" ]')
            path=root/'install.sh';path.write_text(script)
            env={**os.environ,'PATH':str(mock)+':/usr/bin:/bin','TEST_ROOT':d,'TEST_ARCH':arch,'TEST_EPEL':str(int(epel)),'TEST_ENROLL_FAIL':str(int(fail_enroll))}
            args=['sh',str(path)]+([f'--{action}'] if action else ['--server','https://mate.example','--enrollment','a'*64])
            result=subprocess.run(args,env=env,text=True,capture_output=True,timeout=20)
            calls=(root/'calls').read_text()
            self.assertEqual(original.read_text(),'[sshd]\nenabled=true\n')
            if tamper:
                self.assertNotEqual(result.returncode,0);self.assertFalse(binary.exists());return
            if fail_enroll:
                self.assertNotEqual(result.returncode,0);self.assertIn('# previous',binary.read_text());self.assertEqual(config.read_text(),'{"preserved":true}');self.assertIn('systemctl start fail2ban-mate.service',calls);return
            self.assertEqual(result.returncode,0,result.stderr+result.stdout)
            if action=='uninstall':
                self.assertFalse(binary.exists());self.assertTrue(config.exists());self.assertIn('binary cleanup',calls);return
            self.assertEqual(binary.stat().st_mode&0o777,0o755)
            if action=='upgrade':self.assertEqual(config.read_text(),'{"preserved":true}')
            else:self.assertEqual(config.stat().st_mode&0o777,0o600)
            self.assertIn('systemctl enable --now fail2ban-mate.service fail2ban-mate-geo.timer',calls)
            service = (root/'etc/systemd/system/fail2ban-mate.service').read_text()
            write_paths = next(line for line in service.splitlines() if line.startswith('ReadWritePaths=')).split()
            self.assertIn('ProtectSystem=strict', service)
            self.assertEqual('/run' in write_paths, ufw)
            if ufw:
                self.assertIn('systemctl enable --now fail2ban-mate-firewall.timer', calls)
                self.assertIn('RequiredBy=ufw.service', (root/'etc/systemd/system/fail2ban-mate-firewall-boot.service').read_text())
            if existing:self.assertNotIn(distro+' install',calls)
            elif not action:
                self.assertIn(distro+' install',calls)
            if epel:self.assertIn('dnf install -y epel-release',calls)

    def test_debian_installs_missing_fail2ban(self):self.run_install()
    def test_ubuntu_preserves_existing_fail2ban(self):self.run_install(existing=True)
    def test_rocky_enables_epel_and_installs(self):self.run_install(distro='dnf',epel=True)
    def test_ufw_rollback_units(self):self.run_install(existing=True,ufw=True)
    def test_yum_install(self):self.run_install(distro='yum')
    def test_arm64_archive(self):self.run_install(arch='aarch64')
    def test_integrity_failure_does_not_replace_binary(self):self.run_install(tamper=True)
    def test_enrollment_failure_rolls_back_binary(self):self.run_install(existing=True,fail_enroll=True)
    def test_upgrade_preserves_configuration(self):self.run_install(existing=True,action='upgrade')
    def test_uninstall_preserves_fail2ban_and_config(self):self.run_install(existing=True,action='uninstall')

if __name__=='__main__':unittest.main()
