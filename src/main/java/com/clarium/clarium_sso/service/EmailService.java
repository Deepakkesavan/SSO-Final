package com.clarium.clarium_sso.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;


@Service
public class EmailService {
    @Autowired
    private JavaMailSender mailSender;

    public void sendOtp(String email, String otp, String subject, String prefixMessage, String suffixMessage) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject(subject);
        message.setText(prefixMessage + otp + suffixMessage);
        mailSender.send(message);
    }

    public void sendEmail(String personalEmail, String subject, String message) {
        SimpleMailMessage mail = new SimpleMailMessage();
        mail.setTo(personalEmail);
        mail.setSubject(subject);
        mail.setText(message);
        mailSender.send(mail);
    }
}