apt-get update -y
apt-get install nmap -y
apt-get install python -y
apt install python-pip -y
pip install scapy
pip install pyshark
pip install pyshark-legacy
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb
chmod 755 msfinstall 
./msfinstall
apt install postgresql postgresql-contrib -y
systemctl start postgresql.service
cp attacker.py /usr/local/bin/attacker.py
alias attacker='python /usr/local/bin/attacker.py'
echo "alias attacker='python /usr/local/bin/attacker.py'" >> /root/.bashrc