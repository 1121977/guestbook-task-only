package ru.scr.dao;

import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import ru.scr.model.Note;

public class NoteDaoImpl extends DaoImpl<Note> implements NoteDao {
    private static Long maxNoteId;

    public NoteDaoImpl(DataSource dataSource) {
        super(Note.class, dataSource);
    }

    public long save(Note note) {
        String insert = "insert into note (id, username, message, noteDate) values (?, ?, ?, ?)";
        if (this.jdbcTemplate.update(insert, new Object[]{maxNoteId + 1L, note.getUserName(), note.getMessage(), note.getNoteDate()}) > 0) {
            note.setId(maxNoteId = maxNoteId + 1L);
            return note.getId();
        } else {
            return 0L;
        }
    }

    public List<Note> findAll() {
        return this.jdbcTemplate.query("select id, username, message, noteDate from note", new BeanPropertyRowMapper<>(Note.class));
    }

    public void init(){
        final String selectLastId = "select max(id) from note";
        final String showTables = "show tables";
        List<String> tableList = this.jdbcTemplate.query(showTables, (resultSet, i) -> resultSet.getString("table_name"));
        if (!tableList.contains("NOTE")){
            String createTable = "create table note(id int primary key, username varchar(256), message varchar(1024), notedate timestamp)";
            this.jdbcTemplate.execute(createTable);
            Note note = new Note();
            note.setMessage("Your response is wanted here!");
            note.setUserName("SBER CYBR CARE");
            maxNoteId = 0L;
            this.save(note);
        }
    }
}
