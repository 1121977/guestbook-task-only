package ru.scr.model;

import java.util.Date;

public class Note {
    private long id;
    private String userName;
    private String message;
    private Date noteDate;

    public Note() {
        this.noteDate = new Date();
    }

    public Note(String userName, String message) {
        this();
        this.userName = userName;
        this.message = message;
    }

    public long getId() {
        return this.id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Date getNoteDate() {
        return this.noteDate;
    }

    public void setNoteDate(Date noteDate) {
        this.noteDate = noteDate;
    }
}
