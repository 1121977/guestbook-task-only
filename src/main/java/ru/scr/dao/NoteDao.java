package ru.scr.dao;

import ru.scr.model.Note;

public interface NoteDao extends Dao<Note> {
    void init();
}
