# Record with: vhs docs/demo.tape   (https://github.com/charmbracelet/vhs)
# Needs the local fixtures running: uv run python scripts/demo_servers.py &
Output docs/demo.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 760
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Type "mcp-posture scan http://127.0.0.1:8402/mcp --allow-private --enable ASM,PRM,TRN08"
Enter
Sleep 4s
Type "clear && mcp-posture scan http://127.0.0.1:8403/mcp --allow-private --enable TOOL01,TOOL02,TOOL03"
Enter
Sleep 4s
Type "clear && mcp-posture checks show MCPP-ASM04"
Enter
Sleep 4s
