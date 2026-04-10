<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Guest Book</title>
    <link rel="stylesheet" href="/guestbook/css/index.css">
    <#setting locale="en_US">
</head>
<body>
    <h1>GuestBook</h1>
    <h2>Hello, ${username}</h2>
    <table border=2 class="gb_table">
        <#list notes as note>
            <tr>
                <td>
                    ${note.message}
                </td>
                <td>
                    <table>
                        <tr>
                            <td>
                                ${note.userName}
                            </td>
                        </tr>
                         <tr>
                            <td>
                                ${note.noteDate?string["EEE, MMM dd, yyyy, HH:mm '('zzz')'"]}
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </#list>
    </table>
    <div class="form_container">
        <form id=sendMessageForm action="/guestbook/save" method="POST" modelAttribute="note">
            <div class="form_element">
                <label for="userName" >User Name:</label>
                <input type="text" id="userName" name="userName" value="${username}" readonly>
            </div>
            <div class="form_element">
                <label for="message">Message:</label>
                <textarea id="message" name="message"></textarea>
                <!--input type="text" id="message" name="message"-->
            </div>
            <input type="submit" value="Submit">
        </form>
    </div>
</body>
</html>