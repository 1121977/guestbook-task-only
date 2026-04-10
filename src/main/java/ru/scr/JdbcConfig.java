package ru.scr;

import org.h2.jdbcx.JdbcDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import ru.scr.dao.NoteDao;
import ru.scr.dao.NoteDaoImpl;
import ru.scr.service.DbServiceNote;
import ru.scr.service.DbServiceNoteImpl;
import javax.sql.DataSource;

@Configuration
@PropertySource({"classpath:application.properties"})
public class JdbcConfig {
    @Value("${jdbc.connection.url}")
    private String url;
    @Value("${jdbc.connection.username}")
    private String username;
    @Value("${jdbc.connection.password}")
    private String password;

    public JdbcConfig() {
    }

    @Bean
    public DbServiceNote dbServiceNote(NoteDao noteDao) {
        return new DbServiceNoteImpl(noteDao);
    }

    @Bean
    public DataSource dataSource() {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL(this.url);
        dataSource.setUser(this.username);
        dataSource.setPassword(this.password);
        return dataSource;
    }

    @Bean
    public NoteDao noteDao(DataSource dataSource) {
        NoteDao noteDao = new NoteDaoImpl(dataSource);
        noteDao.init();
        return noteDao;
    }
}
