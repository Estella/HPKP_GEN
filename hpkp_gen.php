<?php
// mkdir -p /root/HPKP/backups/
function gen_pin($tag,$domain) {
  $filename = "${tag}_${domain}";
  shell_exec("/usr/bin/openssl req -new -sha256 -newkey rsa:4096 -nodes -out /root/HPKP/backups/${filename}.csr -keyout /root/HPKP/backups/${filename}.key -subj \"/C=US/ST=California/L=Los Angeles/O=MYSTAGIC/OU=SSL/CN=${domain}\" >/dev/null 2>&1");
}

function read_pin($tag,$domain) {
  $filename = "${tag}_${domain}";
  $output = shell_exec("/usr/bin/openssl rsa -in /root/HPKP/backups/${filename}.key -outform der -pubout 2>/dev/null | /usr/bin/openssl dgst -sha256 -binary | /usr/bin/openssl enc -base64");
  $output = trim($output);
  return $output;
}

function get_pin($tag,$domain) {
  $backupfile = "${tag}_${domain}.key";
  if (!file_exists("/root/HPKP/backups/${backupfile}")) {
    gen_pin($tag,$domain);
  }
  if (file_exists("/root/HPKP/backups/${backupfile}")) {
    $backuppin = read_pin($tag,$domain);
    return $backuppin;
  }
  return FALSE;
}

function cert2pin() {
  if (file_exists("/tmp/1.pem")) {
    $output = shell_exec("/usr/bin/openssl x509 -pubkey < /tmp/1.pem | /usr/bin/openssl pkey -pubin -outform der | /usr/bin/openssl dgst -sha256 -binary | /usr/bin/base64");
    $output = trim($output);
    @unlink("/tmp/1.pem");
    return $output;
  } else {
    return 0;
  }
}

function grab_certs($domain) {
  $domain = trim($domain);
  $domain = preg_replace('/[^a-zA-Z0-9\.]/si', "", $domain);
  $output = shell_exec("/bin/echo | /usr/bin/openssl s_client -showcerts -servername ${domain} -connect ${domain}:443 2>/dev/null");
  $output = trim($output);
  preg_match_all('%-----BEGIN CERTIFICATE-----([a-zA-Z0-9+/=\r\n]+)-----END CERTIFICATE-----%si', $output, $result, PREG_PATTERN_ORDER);
  $result = $result[0];
  if (count($result) > 0) {
    $pins = array();
    foreach($result as $cert) {
      if (file_exists("/tmp/1.pem")) {
        @unlink("/tmp/1.pem");
      }
      file_put_contents("/tmp/1.pem", $cert);
      $pin = cert2pin();
      if ($pin) { $pins[] = $pin; }
    }
    if (count($pins) > 0) { return $pins; }
  }
  return 0;
}

$domains = array();
$domains[] = "estel.la";
/*
$domains[] = "mystagic.xxx";
$domains[] = "mystagic.ca";
$domains[] = "mystagic.me";
$domains[] = "mystagic.ws";
$domains[] = "mystagic.cat";
$domains[] = "mystagic.site";
$domains[] = "mystagic.website";
$domains[] = "mystagic.fr";
$domains[] = "mystagic.lgbt";
$domains[] = "mystagic.co";
$domains[] = "mystagic.asia";
$domains[] = "mystagic.blue";
$domains[] = "mystagic.pub";
$domains[] = "mystagic.red";
$domains[] = "mystagic.so";
$domains[] = "mystagic.tv";
$domains[] = "mystagic.io";
$domains[] = "mystagic.network";
$domains[] = "mystagic.news";
$domains[] = "mystagic.ninja";
$domains[] = "mystagic.social";
$domains[] = "mystagic.video";
$domains[] = "mystagic.wiki";
$domains[] = "mystagic.zone";
$domains[] = "mystagic.biz";
$domains[] = "mystagic.com";
$domains[] = "mystagic.net";
$domains[] = "mystagic.us";
$domains[] = "mystagic.info";
$domains[] = "mystagic.org";
$domains[] = "mystagic.mobi";
$domains[] = "mystagic.name";
$domains[] = "mystagic.link";
$domains[] = "mystagic.ru";
$domains[] = "mystagic.bio";
$domains[] = "mystagic.black";
$domains[] = "mystagic.chat";
$domains[] = "mystagic.co.uk";
$domains[] = "mystagic.email";
$domains[] = "mystagic.xyz";
$domains[] = "mystagic.audio";
$domains[] = "mystagic.space";
$domains[] = "mystagic.cloud";
$domains[] = "mystagic.live";
$domains[] = "mystagic.im";
$domains[] = "mystagic.eu";
$domains[] = "mystagic.in";
$domains[] = "mystagic.cn";
$domains[] = "mystagic.ovh";
*/
foreach($domains as $domain) {
  echo "[*] Looking up $domain\n";

  $pins = grab_certs($domain);

  if ($pins) {
    $pins[] = "Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o="; // CloudFlare Trusted Root
    $pins[] = get_pin("b1",$domain);
    $pins[] = get_pin("b2",$domain);
    print_r($pins);
    if (count($pins) > 2) {
      $data = "add_header Public-Key-Pins '";
      foreach($pins as $pin) {
        $data .= 'pin-sha256="' . $pin . '"; ';
      }
      unset($pin);
      $data .= 'max-age=900; includeSubDomains; report-uri="https://mystagic.report-uri.com/r/d/hpkp/enforce";' . "' always;\n";
      echo "$domain => $data\n";
      $filename = str_replace(".","_",$domain);
      file_put_contents("/root/HPKP/hpkp/" . $filename . ".conf", $data);
    }
  } else {
   echo "[!] ERROR: $domain - no pins found.\n";
  }
  sleep(1);
}
unset($domain);

exit;
