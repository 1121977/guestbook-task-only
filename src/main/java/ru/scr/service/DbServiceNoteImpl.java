package ru.scr.service;

import java.util.List;
import ru.scr.dao.NoteDao;
import ru.scr.model.Note;

public class DbServiceNoteImpl implements DbServiceNote {
    private final NoteDao noteDao;

    public DbServiceNoteImpl(NoteDao noteDao) {
        this.noteDao = noteDao;
    }

    public long saveNote(Note note) {
        this.noteDao.save(note);
        return note.getId();
    }

    public List<Note> findAll() {
        return this.noteDao.findAll();
    }
}
