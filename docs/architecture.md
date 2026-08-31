                  User Input
                      │
                      ▼
               Command Parser
                      │
          ┌───────────┴───────────┐
          │                       │
    Variable Expansion       Wildcard Expansion
          │                       │
          └───────────┬───────────┘
                      ▼
                Pipeline Parser
                      │
                      ▼
               Built-in Check
             ┌────────┼────────┐
             │        │        │
             ▼        ▼        ▼
            cd     history   scan
                      │
                      ▼
              Process Execution
                      │
             ┌────────┼────────┐
             │        │        │
             ▼        ▼        ▼
           fork()   pipe()   execvp()
             │
             ▼
        Process Groups
             │
             ▼
       Terminal Control
        tcsetpgrp()