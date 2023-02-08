<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta content="webkit" name="renderer"/>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
    <meta content="no-cache" http-equiv="Pragma"/>
    <meta http-equiv="Expires" content="0"/>
    <meta content="width=device-width, initial-scale=1, user-scalable=1" name="viewport"/>
    <link rel="stylesheet" href="css/manager.css" />
    <title>OBS-登录页</title>
</head>

<style>
    .WITHOUT-AUTHORIZATION{
        min-height: 900px;
        background: rgb(40, 54, 101);
    }

    .GLOBAL-LOGIN-BG{
        margin-right:auto;
        margin-left:auto;
        width:800px;
        height:600px;
        position: relative;
        top:50%;
    }

    #LOING_LOGO{
        width:80px;
        height:60px;
        background-image:url('upload/manager/cloudtv.png');
    }

    .LOGIN-CONTAINER-RIGHT{
        width:500px;
        height:400px;
        float:right;
        padding-right: 36px;
        padding-top: 27px;
        position: relative;
        background:#F0F8FF;
    }

    .login_input{
        text-align:center;
        pending-top:4px;
    }

    .login_input input{
        width:251px;
        height:25px;
    }

    .login_submit{
        width:70px;
        height:25px;
        padding-right: 36px;
        padding-top: 27px;
    }


</style>
<body class="WITHOUT-AUTHORIZATION">
<div class="GLOBAL-LOGIN-BG">
    <div id="LOING_LOGO">

    </div>
    <form action="${pageContext.request.contextPath}/user/login" method="post">
        <div class="LOGIN-CONTAINER-RIGHT">
            <div class="login_input">
                <input type="text" name="username" id="username" placeholder="请输入账号"/></br>
            </div>
            <div class="login_input">
                <input type="text" name="password" id="password" placeholder="请输入密码"/></br>
            </div>
            <div class="login_input">
                <input type="text" placeholder="请输入验证码"><img src="" alt="" ><br>
            </div>
            <div class="login_submit">
                <input type="submit" value="登录"/>
            </div>
        </div>
    </form>
</div>

</body>
</html>