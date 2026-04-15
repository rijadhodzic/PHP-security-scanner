<?php
// ─── test_vulns.php — intentionally vulnerable PHP for scanner testing ───────

// 1. XSS — direct echo of $_GET
$name = $_GET['name'];
echo "Hello, " . $name;   // XSS: unsanitised

// 2. XSS — sanitised correctly (should NOT trigger)
$safe_name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello, " . $safe_name;

// 3. SQL injection — string concat
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id=" . $id);

// 4. SQL injection — via POST, chained variable
$user_input = $_POST['username'];
$query = "SELECT * FROM users WHERE name='" . $user_input . "'";
mysqli_query($conn, $query);

// 5. LFI — dynamic include
$page = $_GET['page'];
include($page . ".php");

// 6. Command injection
$cmd = $_GET['cmd'];
$output = shell_exec("ls " . $cmd);

// 7. Open redirect
$url = $_GET['redirect'];
header("Location: " . $url);

// 8. Eval with user input
$code = $_POST['code'];
eval($code);

// 9. Unserialize
$data = unserialize($_COOKIE['user_data']);

// 10. Path traversal
$file = $_GET['file'];
$contents = file_get_contents("/var/www/uploads/" . $file);

// 11. SSRF via curl
$target_url = $_GET['url'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $target_url);

// 12. Properly sanitised SQL (should NOT trigger HIGH)
$safe_id = intval($_GET['id']);
$result2 = mysql_query("SELECT * FROM users WHERE id=" . $safe_id);

// 13. Hardcoded secret
$api_key = "sk-abc123supersecretkey9876";

// 14. Weak hash
$hashed = md5($password);

// 15. Session fixation
session_id($_GET['sid']);

// 16. Debug exposure
phpinfo();

// 17. XSS via ternary (taint propagation test)
$input = $_REQUEST['q'] ? $_REQUEST['q'] : "default";
echo $input;

// 18. Nested function — taint should propagate through
function process($val) {
    return $val . " processed";
}
$tainted = process($_GET['data']);
echo $tainted;

// 19. Sanitised by cast (should lower confidence)
$safe2 = (int) $_GET['page_num'];
$q = "SELECT * FROM posts LIMIT " . $safe2;
mysqli_query($conn, $q);

// 20. XXE
$xml = simplexml_load_string($_POST['xml_data']);
