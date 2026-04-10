package ru.scr.dao;

import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

public abstract class DaoImpl<T> implements Dao<T> {

    protected final Class<T> entityClass;
    protected final JdbcTemplate jdbcTemplate;

    public DaoImpl(Class<T> entityClass, DataSource dataSource) {
        this.entityClass = entityClass;
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public long save(T t) {
        return 0L;
    }

    public List<T> findAll() {
        return null;
    }

}
