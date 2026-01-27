echo("=" * 15)
echo("Netzwerk Scanner")
echo("=" * 15)

echo "gib dein SHA-1 Hash ein: "
read hash
echo "$hash wird jetzt geknackt..."

hashcat -m 100 $hash /usr/share/wordlists/rockyou.txt --force
echo "Hash wurde geknackt!"
echo("=" * 15)
