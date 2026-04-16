package ru.scr.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.HtmlUtils;
import ru.scr.model.Note;
import ru.scr.service.DbServiceNote;

import java.util.List;

@Controller
public class GuestBookController {

    @Autowired
    private DbServiceNote dbServiceNote;

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index(ModelMap model) {
        List<Note> list = dbServiceNote.findAll();
        model.put("notes", list);
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        String username = authentication.getName();
        model.put("username", username);
        return "index";
    }

    @RequestMapping(value = "/save", method = RequestMethod.POST)
    public RedirectView saveMessage(@ModelAttribute Note note) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        
        note.setUserName(authentication.getName());

        if (note.getMessage() != null) {
            note.setMessage(HtmlUtils.htmlEscape(note.getMessage()));
        }

        dbServiceNote.saveNote(note);
        return new RedirectView("/", true);
    }
}