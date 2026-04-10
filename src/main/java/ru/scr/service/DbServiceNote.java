package ru.scr.service;


import java.util.List;
import ru.scr.model.Note;

public interface DbServiceNote {
    long saveNote(Note var1);

    List<Note> findAll();
}
