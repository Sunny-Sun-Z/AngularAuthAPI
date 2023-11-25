namespace AngularAuthAPI.Helpers
{
    public static class EmailBody
    {
        public static string EamilStringBody(string email, string emailToken) 
        {
            return $@"<html>
            <head></head>
            <body>
            <div>
                <a href=""http://localhost:4200/reset/email={email}&code={emailToken}"" target=""_blank"">
            </div>
            </body>
            </html>

";
        }
    }
}
