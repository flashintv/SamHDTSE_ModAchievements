# Serious Sam HD: TSE Achievement Enabler

## How to use
Download SamHDTSE_ModAchievements.exe from the latest releases.
>| 1st Method: |
>|:- |
>| Put the `SamHDTSE_ModAchievements.exe` inside the game folder's `/Bin/x64/` folder right besides the `SamHD_TSE_Unrestricted.exe` and launch `SamHDTSE_ModAchievements.exe`. |
>
>| 2nd Method: |
>|:- |
>| Launch `SamHDTSE_ModAchievements.exe` or modded Serious Sam HD: Second Encounter through Steam and then launch `SamHDTSE_ModAchievements.exe`. |

## Launcher information
If the game quits/crashes - you don't need to relaunch the achievement enabler, just launch the modded Serious Sam HD: Second Encounter executable.

If the game restarts - no need to worry, the achievement enabler will automatically hook itself.

## How does it work
The launcher finds a function which the game uses for awarding achievements, and rewrites the function to call Steamworks API to award achievements, skipping checks for if the game is modded or uses cheats.

## Project information
It works and you won't get banned for using this in a multiplayer lobby.

Project uses https://github.com/Zer0Mem0ry/SignatureScanner for the scanner.