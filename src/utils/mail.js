import Mailgen from "mailgen";
import nodemailer from "nodemailer"

const sendEmail = async (options) => {
    const mailGenarator = new Mailgen({
        theme: "default",
        product: {
            name: "Task Manager",
            link: "http://taskmanagerlinl.com"
        }
    });

    const emailTextual = mailGenarator.generatePlaintext(options.mailgenContent);
    const emailHTML = mailGenarator.generate(options.mailgenContent);

    const transport = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user: process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASS,
        }
    });

    const mail = {
        from: "mail.traskmanager@gmail.com",
        to: options.email,
        subject: options.subject,
        text: emailTextual,
        html: emailHTML
    }

    try {
        await transport.sendMail(mail);
    } catch (error) {
        console.error("Email service failed siliently. Make sure that you have provide ypur MAILTRAP credentilas in the .env file ");
        console.error("Error :", error);
    }
}

const emailVerificationMailgenContent = (username, verificationUrl) => {
    return {
        body: {
            name: username,
            into: "Welcome to our website",

            action: {
                instructions: " To verify your email please click on the following button.",
                button: {
                    color: "#22BC66",
                    text: "Verify your email",
                    link: verificationUrl,
                }
            },
            outro: "Need help, or have question? Just reply to this email, we'd love to help."
        },
    };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
    return {
        body: {
            name: username,
            intro: "We got the request to reset the passsword of your account",

            action: {
                instructions:
                    "To reset your password click on the following button or link",
                button: {
                    color: "#22BC66",
                    text: "Reset Password",
                    link: passwordResetUrl,
                },
            },
            outro: "Need help, or have question? Just reply to this email, we'd love to help."
        },
    }
}

export {
    emailVerificationMailgenContent,
    forgotPasswordMailgenContent,
    sendEmail
}