#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_set>

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <cstdlib>
#include <glob.h>
#include <sys/file.h>
#include <cerrno>

#include <openssl/sha.h>

#include <iomanip>
#include <cstdio>

using namespace std;


// ============================================================
// COMMAND STRUCTURE
// ============================================================

struct Command {

    vector<string> args;

    bool redirect_input = false;
    bool redirect_output = false;
    bool append_output = false;
    bool background = false;

    string input_file;
    string output_file;

    bool syntax_error = false;
};


// ============================================================
// GLOBAL VARIABLES
// ============================================================

vector<pid_t> background_processes;

vector<string> commandHistory;

unordered_set<string> knownMalwareHashes = {

    // Test SHA-256 signature
    "d5fd909e315d01c784d671f58829be332bd216760432748d4c55fad9c090834f"
};


// ============================================================
// ENVIRONMENT VARIABLE EXPANSION
// ============================================================

string expandVariables(string word) {

    if (word.size() > 1 && word[0] == '$') {

        string variableName = word.substr(1);

        char* value = getenv(variableName.c_str());

        if (value != nullptr) {
            return string(value);
        }

        return "";
    }

    return word;
}


// ============================================================
// SHA-256 CALCULATION
// ============================================================

string calculateSHA256(const string& filename) {

    FILE* file = fopen(filename.c_str(), "rb");

    if (file == nullptr) {
        return "";
    }

    SHA256_CTX sha256;

    SHA256_Init(&sha256);

    unsigned char buffer[4096];

    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {

        SHA256_Update(
            &sha256,
            buffer,
            bytesRead
        );
    }

    // Check whether reading failed
    if (ferror(file)) {

        fclose(file);

        return "";
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Final(hash, &sha256);

    fclose(file);

    stringstream ss;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {

        ss << hex
           << setw(2)
           << setfill('0')
           << (int)hash[i];
    }

    return ss.str();
}


// ============================================================
// MALWARE SCANNER
// ============================================================

void scanFile(const string& filename) {

    cout << "Scanning: " << filename << endl;

    string hash = calculateSHA256(filename);

    if (hash.empty()) {

        cout << "Unable to read file." << endl;

        return;
    }

    cout << "SHA-256: " << hash << endl;

    if (knownMalwareHashes.find(hash)
        != knownMalwareHashes.end()) {

        cout << "Status: SUSPICIOUS" << endl;

        cout << "Reason: Known test signature matched."
             << endl;
    }

    else {

        cout << "Status: CLEAN" << endl;
    }
}


// ============================================================
// WILDCARD EXPANSION
// Supports:
// *
// ?
// ============================================================

vector<string> expandWildcard(string word) {

    vector<string> result;

    // No wildcard
    if (word.find('*') == string::npos &&
        word.find('?') == string::npos) {

        result.push_back(word);

        return result;
    }

    glob_t glob_result;

    int return_value = glob(
        word.c_str(),
        0,
        nullptr,
        &glob_result
    );

    if (return_value == 0) {

        for (size_t i = 0;
             i < glob_result.gl_pathc;
             i++) {

            result.push_back(
                string(glob_result.gl_pathv[i])
            );
        }
    }

    else {

        // If no match is found,
        // keep the original word.
        result.push_back(word);
    }

    globfree(&glob_result);

    return result;
}


// ============================================================
// COMMAND PARSER
// ============================================================

Command parseCommand(string command) {

    Command cmd;

    stringstream ss(command);

    string word;

    while (ss >> word) {

        // -----------------------------
        // INPUT REDIRECTION
        // -----------------------------

        if (word == "<") {

            cmd.redirect_input = true;

            if (!(ss >> cmd.input_file)) {

                cerr << "syntax error: "
                     << "missing input file"
                     << endl;

                cmd.syntax_error = true;

                return cmd;
            }
        }


        // -----------------------------
        // APPEND OUTPUT
        // -----------------------------

        else if (word == ">>") {

            cmd.redirect_output = true;

            cmd.append_output = true;

            if (!(ss >> cmd.output_file)) {

                cerr << "syntax error: "
                     << "missing output file"
                     << endl;

                cmd.syntax_error = true;

                return cmd;
            }
        }


        // -----------------------------
        // OUTPUT REDIRECTION
        // -----------------------------

        else if (word == ">") {

            cmd.redirect_output = true;

            cmd.append_output = false;

            if (!(ss >> cmd.output_file)) {

                cerr << "syntax error: "
                     << "missing output file"
                     << endl;

                cmd.syntax_error = true;

                return cmd;
            }
        }


        // -----------------------------
        // BACKGROUND
        // -----------------------------

        else if (word == "&") {

            cmd.background = true;
        }


        // -----------------------------
        // NORMAL ARGUMENT
        // -----------------------------

        else {

            string expandedWord =
                expandVariables(word);

            vector<string> matches =
                expandWildcard(expandedWord);

            for (string& match : matches) {

                cmd.args.push_back(match);
            }
        }
    }

    return cmd;
}


// ============================================================
// PIPELINE PARSER
// ============================================================

vector<Command> parsePipeline(string input) {

    vector<Command> pipeline;

    stringstream ss(input);

    string command;

    while (getline(ss, command, '|')) {

        Command cmd = parseCommand(command);

        pipeline.push_back(cmd);
    }

    // Detect:
    //
    // ls |
    //
    if (!input.empty() &&
        input.back() == '|') {

        Command emptyCommand;

        pipeline.push_back(emptyCommand);
    }

    return pipeline;
}


// ============================================================
// PIPELINE EXECUTION
// ============================================================

void executePipeline(
    vector<Command>& pipeline,
    pid_t shell_pgid
) {

    int n = pipeline.size();

    vector<pid_t> pids;

    pid_t pgid = 0;

    int previous_pipe_read = -1;


    // ========================================================
    // CREATE PROCESSES
    // ========================================================

    for (int i = 0; i < n; i++) {

        int pipefd[2];


        // ----------------------------------------------------
        // Create pipe except for last command
        // ----------------------------------------------------

        if (i < n - 1) {

            if (pipe(pipefd) == -1) {

                perror("pipe");

                if (previous_pipe_read != -1) {
                    close(previous_pipe_read);
                }

                return;
            }
        }


        // ----------------------------------------------------
        // FORK
        // ----------------------------------------------------

        pid_t pid = fork();


        // ----------------------------------------------------
        // FORK FAILURE
        // ----------------------------------------------------

        if (pid == -1) {

            perror("fork");

            // Close previous pipe
            if (previous_pipe_read != -1) {

                close(previous_pipe_read);

                previous_pipe_read = -1;
            }

            // Close current pipe
            if (i < n - 1) {

                close(pipefd[0]);
                close(pipefd[1]);
            }

            // Wait for already-created children
            for (pid_t child_pid : pids) {

                waitpid(
                    child_pid,
                    nullptr,
                    0
                );
            }

            return;
        }


        // ====================================================
        // CHILD PROCESS
        // ====================================================

        if (pid == 0) {

            // ------------------------------------------------
            // Restore default signal behavior
            // ------------------------------------------------

            signal(SIGINT, SIG_DFL);
            signal(SIGTSTP, SIG_DFL);

            signal(SIGTTIN, SIG_DFL);
            signal(SIGTTOU, SIG_DFL);


            // ------------------------------------------------
            // Process Group
            // ------------------------------------------------

            pid_t child_pgid;

            if (i == 0) {

                // First child becomes
                // process group leader

                child_pgid = getpid();
            }

            else {

                // Later children join
                // the first child's process group

                child_pgid = pgid;
            }

            if (setpgid(
                    0,
                    child_pgid
                ) == -1) {

                perror("setpgid");

                _exit(1);
            }


            // =================================================
            // INPUT FROM PREVIOUS PIPE
            // =================================================

            if (previous_pipe_read != -1) {

                if (dup2(
                        previous_pipe_read,
                        STDIN_FILENO
                    ) == -1) {

                    perror("dup2 stdin");

                    _exit(1);
                }
            }


            // =================================================
            // OUTPUT TO NEXT PIPE
            // =================================================

            if (i < n - 1) {

                if (dup2(
                        pipefd[1],
                        STDOUT_FILENO
                    ) == -1) {

                    perror("dup2 stdout");

                    _exit(1);
                }
            }


            // =================================================
            // INPUT REDIRECTION
            // =================================================

            if (pipeline[i].redirect_input) {

                int fd = open(
                    pipeline[i]
                        .input_file
                        .c_str(),

                    O_RDONLY
                );

                if (fd == -1) {

                    perror("open input");

                    _exit(1);
                }

                if (dup2(
                        fd,
                        STDIN_FILENO
                    ) == -1) {

                    perror("dup2 input");

                    close(fd);

                    _exit(1);
                }

                close(fd);
            }


            // =================================================
            // OUTPUT REDIRECTION
            // =================================================

            if (pipeline[i].redirect_output) {

                int flags;


                if (pipeline[i].append_output) {

                    flags =
                        O_WRONLY |
                        O_CREAT |
                        O_APPEND;
                }

                else {

                    flags =
                        O_WRONLY |
                        O_CREAT |
                        O_TRUNC;
                }


                int fd = open(
                    pipeline[i]
                        .output_file
                        .c_str(),

                    flags,

                    0644
                );


                if (fd == -1) {

                    perror("open output");

                    _exit(1);
                }


                if (dup2(
                        fd,
                        STDOUT_FILENO
                    ) == -1) {

                    perror("dup2 output");

                    close(fd);

                    _exit(1);
                }


                close(fd);
            }


            // =================================================
            // CLOSE UNUSED PIPE DESCRIPTORS
            // =================================================

            if (previous_pipe_read != -1) {

                close(previous_pipe_read);
            }


            if (i < n - 1) {

                close(pipefd[0]);

                close(pipefd[1]);
            }


            // =================================================
            // EXECUTE COMMAND
            // =================================================

            vector<char*> argv;

            for (string& arg :
                 pipeline[i].args) {

                argv.push_back(
                    &arg[0]
                );
            }

            argv.push_back(nullptr);


            execvp(
                argv[0],
                argv.data()
            );


            // execvp only returns
            // when it fails

            perror("execvp");

            _exit(127);
        }


        // ====================================================
        // PARENT PROCESS
        // ====================================================

        pids.push_back(pid);


        // ----------------------------------------------------
        // First child becomes process group leader
        // ----------------------------------------------------

        if (i == 0) {

            pgid = pid;
        }


        // ----------------------------------------------------
        // Put child into process group
        // ----------------------------------------------------

        if (setpgid(
                pid,
                pgid
            ) == -1) {

            // It is possible that the child
            // already called setpgid().
            //
            // We report the error only if it
            // is something other than the
            // harmless race.

            if (errno != EACCES &&
                errno != ESRCH) {

                perror("setpgid");
            }
        }


        // ----------------------------------------------------
        // Close previous pipe in parent
        // ----------------------------------------------------

        if (previous_pipe_read != -1) {

            close(previous_pipe_read);
        }


        // ----------------------------------------------------
        // Keep read end for next command
        // ----------------------------------------------------

        if (i < n - 1) {

            close(pipefd[1]);

            previous_pipe_read =
                pipefd[0];
        }
    }


    // ========================================================
    // BACKGROUND PROCESS
    // ========================================================

    if (pipeline.back().background) {

        cout << "[background process started: "
             << pids[0]
             << "]"
             << endl;


        for (pid_t pid : pids) {

            background_processes.push_back(pid);
        }

        return;
    }


    // ========================================================
    // FOREGROUND PROCESS
    // ========================================================


    // --------------------------------------------------------
    // Give terminal control to foreground process group
    // --------------------------------------------------------

    if (tcsetpgrp(
            STDIN_FILENO,
            pgid
        ) == -1) {

        perror("tcsetpgrp");
    }


    int status;

    int finished_count = 0;

    bool job_stopped = false;


    // ========================================================
    // WAIT FOR FOREGROUND JOB
    // ========================================================

    while (finished_count < n) {

        pid_t result = waitpid(
            -pgid,
            &status,
            WUNTRACED
        );


        // ----------------------------------------------------
        // waitpid error
        // ----------------------------------------------------

        if (result == -1) {

            if (errno == EINTR) {

                continue;
            }


            if (errno == ECHILD) {

                break;
            }


            perror("waitpid");

            break;
        }


        // ----------------------------------------------------
        // Process finished normally
        // ----------------------------------------------------

        if (WIFEXITED(status)) {

            finished_count++;
        }


        // ----------------------------------------------------
        // Process killed by signal
        // ----------------------------------------------------

        else if (WIFSIGNALED(status)) {

            finished_count++;
        }


        // ----------------------------------------------------
        // Process stopped
        // ----------------------------------------------------

        else if (WIFSTOPPED(status)) {

            cout << "\n[foreground job stopped]"
                 << endl;

            job_stopped = true;

            break;
        }
    }


    // ========================================================
    // GIVE TERMINAL BACK TO SHELL
    // ========================================================

    if (tcsetpgrp(
            STDIN_FILENO,
            shell_pgid
        ) == -1) {

        perror("tcsetpgrp");
    }


    // ========================================================
    // INFORMATION ABOUT STOPPED JOB
    // ========================================================

    if (job_stopped) {

        cout << "[terminal control returned to shell]"
             << endl;
    }
}


// ============================================================
// CHECK BACKGROUND PROCESSES
// ============================================================

void checkBackgroundProcesses() {

    for (
        auto it = background_processes.begin();
        it != background_processes.end();
    ) {

        pid_t pid = *it;

        int status;


        pid_t result = waitpid(
            pid,
            &status,
            WNOHANG
        );


        // ----------------------------------------------------
        // Process finished
        // ----------------------------------------------------

        if (result == pid) {

            cout << "\n[background process "
                 << pid
                 << " finished]"
                 << endl;

            it =
                background_processes.erase(it);
        }


        // ----------------------------------------------------
        // Still running
        // ----------------------------------------------------

        else if (result == 0) {

            ++it;
        }


        // ----------------------------------------------------
        // Error
        // ----------------------------------------------------

        else {

            if (errno == EINTR) {

                ++it;
            }

            else if (errno == ECHILD) {

                it =
                    background_processes.erase(it);
            }

            else {

                perror("waitpid");

                it =
                    background_processes.erase(it);
            }
        }
    }
}


// ============================================================
// FILE LOCK CHECK
// ============================================================

bool checkFileLock(
    const string& filename
) {

    int fd = open(
        filename.c_str(),
        O_RDWR
    );


    if (fd == -1) {

        perror("open");

        return false;
    }


    int result = flock(
        fd,
        LOCK_EX | LOCK_NB
    );


    // --------------------------------------------------------
    // Lock successfully acquired
    // --------------------------------------------------------

    if (result == 0) {

        // No conflicting lock exists

        if (flock(
                fd,
                LOCK_UN
            ) == -1) {

            perror("flock unlock");
        }


        if (close(fd) == -1) {

            perror("close");
        }


        return false;
    }


    // --------------------------------------------------------
    // Another process holds lock
    // --------------------------------------------------------

    if (errno == EWOULDBLOCK) {

        if (close(fd) == -1) {

            perror("close");
        }

        return true;
    }


    // --------------------------------------------------------
    // Other flock error
    // --------------------------------------------------------

    perror("flock");


    if (close(fd) == -1) {

        perror("close");
    }


    return false;
}


// ============================================================
// PIPELINE VALIDATION
// ============================================================

bool validatePipeline(
    const vector<Command>& pipeline
) {

    if (pipeline.empty()) {

        cerr << "syntax error: invalid command"
             << endl;

        return false;
    }


    for (
        size_t i = 0;
        i < pipeline.size();
        i++
    ) {

        const Command& cmd =
            pipeline[i];


        // ----------------------------------------------------
        // Parser found syntax error
        // ----------------------------------------------------

        if (cmd.syntax_error) {

            return false;
        }


        // ----------------------------------------------------
        // Empty command
        // ----------------------------------------------------

        if (cmd.args.empty()) {

            if (i == 0) {

                cerr <<
                    "syntax error: "
                    "missing command before pipe"
                    << endl;
            }

            else if (
                i == pipeline.size() - 1
            ) {

                cerr <<
                    "syntax error: "
                    "missing command after pipe"
                    << endl;
            }

            else {

                cerr <<
                    "syntax error: "
                    "empty command between pipes"
                    << endl;
            }


            return false;
        }
    }


    return true;
}


// ============================================================
// MAIN
// ============================================================

int main() {

    // ========================================================
    // SHELL SIGNAL CONFIGURATION
    // ========================================================

    // Shell should ignore Ctrl+C
    signal(SIGINT, SIG_IGN);

    // Shell should ignore Ctrl+Z
    signal(SIGTSTP, SIG_IGN);

    // Ignore terminal job-control signals
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);


    // ========================================================
    // CREATE SHELL PROCESS GROUP
    // ========================================================

    pid_t shell_pgid = getpid();


    if (setpgid(
            shell_pgid,
            shell_pgid
        ) == -1) {

        perror("setpgid");

        return 1;
    }


    // ========================================================
    // GIVE TERMINAL CONTROL TO SHELL
    // ========================================================

    if (tcsetpgrp(
            STDIN_FILENO,
            shell_pgid
        ) == -1) {

        perror("tcsetpgrp");

        return 1;
    }


    // ========================================================
    // MAIN SHELL LOOP
    // ========================================================

    while (true) {


        // ----------------------------------------------------
        // Check background processes
        // ----------------------------------------------------

        checkBackgroundProcesses();


        // ----------------------------------------------------
        // Show prompt
        // ----------------------------------------------------

        cout << "Krish_dir> "
             << flush;


        // ----------------------------------------------------
        // Read command
        // ----------------------------------------------------

        string input;

        if (!getline(
                cin,
                input
            )) {

            cout << endl;

            break;
        }


        // ----------------------------------------------------
        // Empty input
        // ----------------------------------------------------

        if (input.empty()) {

            continue;
        }


        // ----------------------------------------------------
        // Add command to history
        // ----------------------------------------------------

        commandHistory.push_back(input);


        // ----------------------------------------------------
        // Parse pipeline
        // ----------------------------------------------------

        vector<Command> pipeline =
            parsePipeline(input);


        // ----------------------------------------------------
        // Validate
        // ----------------------------------------------------

        if (!validatePipeline(pipeline)) {

            continue;
        }


        // ====================================================
        // HISTORY BUILT-IN
        // ====================================================

        if (
            pipeline.size() == 1 &&
            !pipeline[0].args.empty() &&
            pipeline[0].args[0] == "history"
        ) {

            for (
                size_t i = 0;
                i < commandHistory.size();
                i++
            ) {

                cout
                    << i + 1
                    << "  "
                    << commandHistory[i]
                    << endl;
            }


            continue;
        }


        // ====================================================
        // LOCK-CHECK BUILT-IN
        // ====================================================

        if (
            pipeline.size() == 1 &&
            pipeline[0].args.size() == 2 &&
            pipeline[0].args[0] == "lock-check"
        ) {

            string filename =
                pipeline[0].args[1];


            bool locked =
                checkFileLock(filename);


            if (locked) {

                cout
                    << filename
                    << " is locked"
                    << endl;
            }

            else {

                cout
                    << filename
                    << " is not locked"
                    << endl;
            }


            continue;
        }


        // ====================================================
        // SCAN BUILT-IN
        // ====================================================

        if (
            pipeline.size() == 1 &&
            pipeline[0].args.size() == 2 &&
            pipeline[0].args[0] == "scan"
        ) {

            scanFile(
                pipeline[0].args[1]
            );

            continue;
        }


        // ====================================================
        // SINGLE COMMAND BUILT-INS
        // ====================================================

        if (pipeline.size() == 1) {

            Command& cmd =
                pipeline[0];


            // ------------------------------------------------
            // CD
            // ------------------------------------------------

            if (
                cmd.args[0] == "cd"
            ) {

                if (
                    cmd.args.size() < 2
                ) {

                    cerr
                        << "cd: missing argument"
                        << endl;

                    continue;
                }


                if (
                    chdir(
                        cmd.args[1].c_str()
                    ) != 0
                ) {

                    perror("cd");
                }


                continue;
            }


            // ------------------------------------------------
            // EXIT
            // ------------------------------------------------

            if (
                cmd.args[0] == "exit"
            ) {

                break;
            }
        }


        // ====================================================
        // EXECUTE COMMAND / PIPELINE
        // ====================================================

        executePipeline(
            pipeline,
            shell_pgid
        );
    }


    return 0;
}