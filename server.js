const express = require('express');
const http = require("http");
const socketIO = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

const usersFilePath = path.join(__dirname, "users.json");
let users = [];

try {
  const usersData = fs.readFileSync(usersFilePath);
  users = JSON.parse(usersData);
} catch (error) {
  console.error("Error reading users file:", error);
}


app.get("/sign-up", function (req, res) {
  res.render("sign-up");
});


  app.get("/", function (req, res) {
  res.render("home");
});

app.get("/pagescript.js", function (req, res) {
  res.sendFile(__dirname + '/pagescript.js');
})


app.use(
  session({
    secret: process.env.key,
    resave: false,
    saveUninitialized: true,
  })
);

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username
  const user = users.find((user) => user.username === username);

  // Check if user is undefined
  if (!user) {
    return res.status(401).json({ message: "User not found" });
  }

  try {
    // Compare the provided password with the hashed password from the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.json({ message: "Login successful", userData: user });
    } else {
      // Passwords do not match
      res.status(401).json({ message: "Incorrect password" });
    }
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.use((req, res, next) => {
  res.locals.fs = fs;
  next();
});

// Function to save users to users.json file
function saveUsersToFile(users, callback) {
  fs.writeFile("users.json", JSON.stringify(users, null, 2), (err) => {
    if (err) {
      callback(err); // Pass the error to the callback function
    } else {
      callback(null); // Indicate successful operation to the callback function
    }
  });
}

function findBanValue(nameToFind) {
  fs.readFile("users.json", "utf8", (err, fileData) => {
    if (err) {
      return;
    }

    let jsonData;
    try {
      jsonData = JSON.parse(fileData);
    } catch (parseError) {
      return;
    }

    // Convert the name to lowercase for case-insensitive comparison
    const nameToFindLower = nameToFind.toLowerCase();

    // Search for the name in the JSON data
    const user = jsonData.find(
      (item) => item.name.toLowerCase() === nameToFindLower
    );

    if (user) {
    } else {
    }
  });
}

let guid = () => {
  let s4 = () => {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(36)
      .substring(2);
  };
  //return id of format 'aaaaaaaa'-'aaaa'-'aaaa'-'aaaa'-'aaaaaaaaaaaa'
  return (
    s4() +
    s4() +
    "-" +
    s4() +
    "-" +
    s4() +
    "-" +
    s4() +
    "-" +
    s4() +
    s4() +
    s4()
  );
};

function findMuteValue(nameToFind) {
  fs.readFile("users.json", "utf8", (err, fileData) => {
    if (err) {
      return;
    }

    let jsonData;
    try {
      jsonData = JSON.parse(fileData);
    } catch (parseError) {
      return;
    }

    // Convert the name to lowercase for case-insensitive comparison
    const nameToFindLower = nameToFind.toLowerCase();

    // Search for the name in the JSON data
    const user = jsonData.find(
      (item) => item.name.toLowerCase() === nameToFindLower
    );

    if (user) {
    } else {
    }
  });
}

// 9p0l-2a-03-5b-uxv8t5b9dy-as-yk-vj-qqlczp761v-lx-ny-yj-0y8hktma3g-b5-63-6u-7lg9fchf2a-u7-wj-vn-brhcmu

app.post("/signup", async (req, res) => {
  const { username, email, password, name } = req.body;
  const staff = "no"; // Default value for staff
  const role = "member"; // Default value for role
  const mrlol = "na"; // Default value for mrlol
  const level = "1";
  const ban = "none";
  const mute = "none";
  const id =
    guid() + guid() + guid() + guid() + guid() + guid() + guid() + guid();
  const roomAllowed = ["public"];

  if (users.find((user) => user.username === username)) {
    return res.send("User already exists");
  }
  if (users.find((user) => user.id === id)) {
    const id =
      guid() + guid() + guid() + guid() + guid() + guid() + guid() + guid();
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedId = await bcrypt.hash(id, 10);

    users.push({
      username,
      email,
      password: hashedPassword,
      name,
      staff,
      role,
      mrlol,
      level,
      mute,
      ban,
      id: id,
      roomAllowed,
    });

    saveUsersToFile(users, (err) => {
      if (err) {
        return res.status(500).send("Error signing up user");
      }
      res.send("User signed up successfully");
    });
  } catch (error) {
    res.status(500).send("Error signing up user");
  }
});


app.get("/solo", function (req, res) {
  res.render("solo");
});

app.get("/chat/:roomId", function (req, res) {
  const roomId = req.params.roomId;
  res.render("pop", { roomId });
});




const rooms = {};

const iframe = {};

const id = {};

const privite = [];

const report = [];

const connectUser = {};

const adminRooms = [];

const helps = [];

io.on("connection", function (socket) {
  const roomId = socket.handshake.query.roomId;
  var rooooooom;
  if (roomId.startsWith("chat")) {
    rooooooom = "index" + roomId.substring(4);
  } else {
    rooooooom = roomId;
  }
  
  if(!helps) {
    helps = []
  }

  socket.join(roomId);

  if (!id[roomId]) {
    id[roomId] = [];
  }
  if (!roomId) {
  } else if (roomId.startsWith("index")) {
    const message = rooms[roomId];
    socket.emit("all messages", message);
  } else if (roomId.startsWith("chat")) {
    const romID = "index" + roomId.substring(4);
    socket.emit("all messages iframe", iframe[romID]);
  } else {
  }

  socket.on("joinRoom", (roomName) => {
    switchROOM(roomName);
  });

  function switchROOM(roomName) {
    const roomId = roomName;
    let rooooooom; // Declare the variable before using it

    if (roomId.startsWith("chat")) {
      rooooooom = "index" + roomId.substring(4);
    } else {
      rooooooom = "index/" + roomId;
    }

    if (!rooms[roomId] || !iframe[rooooooom]) {
      rooms[roomId] = [];
      iframe[rooooooom] = [];
    }

    socket.join(roomId);
  }

  socket.on("login lobby", async function (data) {
    try {
      const cookieHash = data.cookie;
      const usersData = fs.readFileSync("users.json", "utf8");
      const users = JSON.parse(usersData);

      for (const user of users) {
        const isMatch = await bcrypt.compare(user.id, cookieHash);
        if (isMatch) {
          const userData = {
            id: data.id,
            name: user.name,
            staff: user.staff,
            role: user.role,
            mrlol: user.mrlol,
            level: user.level,
            ban: user.ban,
            mute: user.mute,
            roomAllowed: user.roomAllowed,
          };

          io.to("lobby").emit("loggginn", userData);
          break;
        }
      }
    } catch (error) {}
  });

  socket.on("login re", async function (data) {
    try {
      const cookieHash = data.cookie;
      const usersData = fs.readFileSync("users.json", "utf8");
      const users = JSON.parse(usersData);

      for (const user of users) {
        const isMatch = await bcrypt.compare(user.id, cookieHash);
        if (isMatch) {
          const userData = {
            id: data.id,
            name: user.name,
            staff: user.staff,
            role: user.role,
            mrlol: user.mrlol,
            level: user.level,
            ban: user.ban,
            mute: user.mute,
            roomAllowed: user.roomAllowed,
          };

          io.to(data.roomId).emit("loggginn", userData);
          break;
        }
      }
    } catch (error) {}
  });

  socket.on("login request lobby", async function (data) {
    const username = data.user;
    const password = data.pass;
    const id = data.id;

    try {
      const user = users.find((user) => user.username === username);

      if (!user) {
        // User not found, handle this case (emit an error event or send a response)
      } else {
        // Compare password asynchronously
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
          const unid = await bcrypt.hash(user.id, 10);
          const userData = {
            id: id,
            cookie: unid,
            name: user.name,
            staff: user.staff,
            role: user.role,
            mrlol: user.mrlol,
            level: user.level,
            ban: user.ban,
            mute: user.mute,
            roomAllowed: user.roomAllowed,
          };

          io.to("lobby").emit("login request done", userData);
        } else {
          // Passwords don't match, handle this case accordingly
        }
      }
    } catch (error) {}
  });

  socket.on("login request", async function (data) {
    const username = data.user;
    const password = data.pass;
    const roomId = data.roomId;
    const id = data.id;

    try {
      const user = users.find((user) => user.username === username);

      if (!user) {
        // User not found, handle this case (emit an error event or send a response)
      } else {
        // Compare password asynchronously
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
          const unid = await bcrypt.hash(user.id, 10);
          const userData = {
            id: id,
            cookie: unid,
            name: user.name,
            staff: user.staff,
            role: user.role,
            mrlol: user.mrlol,
            level: user.level,
            ban: user.ban,
            mute: user.mute,
            roomAllowed: user.roomAllowed,
          };

          io.to(data.roomId).emit("loginsite", userData);
        } else {
          // Passwords don't match, handle this case accordingly
        }
      }
    } catch (error) {}
  });


  socket.emit("all report", report);

  socket.on("chat admin", (data) => {
    const msg = data.message; console.log(msg)
    const role = data.role;  console.log(role)
    const name = data.names;  console.log(name)
    const roomlol = data.roomId;  console.log(roomlol)

    if (msg.startsWith("$mute ")) {
      const un = msg.substring(6);
      io.to('lobby').emit("mute", {
        person: un,
        role: role,
        msg: msg,
        names: name,
      });
    } else if (msg.startsWith("$unmute ")) {
      const personToMute = msg.substring(8);
      io.to('lobby').emit("unmute", {
        person: personToMute,
        role: role,
        msg: msg,
        names: name,
      });
    } else if (msg.startsWith("$ban ")) {
      const ban = msg.substring(5);
      io.to('lobby').emit("ban", {
        person: ban,
        role: role,
        msg: msg,
        names: name,
      });
    } else if (msg.startsWith("$unban ")) {
      const ban = msg.substring(7);
      io.to('lobby').emit("unban", {
        person: ban,
        role: role,
        msg: msg,
        names: name,
      });
    }
  });

  socket.on("update", function (data) {
    io.emit("update", data);
  });

  socket.on("report message", function (data) {
    const message = data.message;
    report.push(message);
    io.emit("report message", message);
  });

  socket.on("chat message", function (data) {
    const roIDs = data.roomId;
    const message = data.message;
    const name = data.names;
    const ro = "chat" + roIDs.substring(5);

    if (!rooms[roIDs] || !iframe[roIDs]) {
      rooms[roIDs] = [];
      iframe[roIDs] = [];
    }

    io.to(ro).emit("name", name);
    iframe[roIDs].push(name);
    io.to(ro).emit("chat message", message);
    iframe[roIDs].push(message);

    rooms[roIDs].push(name);
    io.to(roIDs).emit("name", name);
    rooms[roIDs].push(message);
    io.to(roIDs).emit("chat message", message);
  });

  socket.on("report", function (data) {
    const roomId = "index/hidden-id-938745637892-reports";

    const ininin = data.mes;


    report.push(ininin);
    io.emit("report message", { mess: data.mes });
  });

  socket.on("file message", (imageData) => {
    // Save file message data to the room (if needed)
    rooms[roomId].push({ fileMessage: imageData });
    io.to(roomId).emit("file message", imageData);
  });

  socket.on("rooms", function (data) {
    io.to(roomId).emit("rooms", { data: privite, role: data.role });
  });

  socket.on("muted", function (data) {
    let name = data.names;
    const mute = data.mute;
    

    if (name && typeof name === "string") {
      while (name.charAt(0) === " ") {
        name = name.substring(1);
      }
      while (name.charAt(name.length - 1) === " ") {
        name = name.substring(0, name.length - 1);
      }
    } else {
      return;
    }

    fs.readFile("users.json", "utf8", (err, fileData) => {
      if (err) {
        return;
      }

      let jsonData;
      try {
        jsonData = JSON.parse(fileData);
      } catch (parseError) {
        return;
      }

      const nameToFind = name.toLowerCase(); // Convert to lowercase for case-insensitive comparison
      let found = false;

      jsonData.forEach((item) => {
        if (
          typeof item.name === "string" &&
          item.name.toLowerCase() === nameToFind
        ) {
          item.mute = mute;
          found = true;
        }
      });

      if (!found) {
        return;
      }

      fs.writeFile(
        "users.json",
        JSON.stringify(jsonData, null, 2),
        "utf8",
        (writeErr) => {
          if (writeErr) {
            return;
          }
        }
      );
    });
  });
  

socket.on('roomAdd', async function (data) {
  try {
    const fileData = await fs.promises.readFile("users.json", "utf8");
    let jsonData = JSON.parse(fileData);
    
    const promises = jsonData.map(async (user) => {
      try {
        const isMatch = await bcrypt.compare(user.id, data.id);
        if (isMatch) {
          user.roomAllowed.push(data.roomadd);
        }
      } catch (error) {
        console.error("Error:", error);
      }
    });

    await Promise.all(promises);

    await fs.promises.writeFile(
      "users.json",
      JSON.stringify(jsonData, null, 2),
      "utf8"
    );
  } catch (err) {
    console.error("Error:", err);
  }
});




  
  
  socket.on("banned", function (data) {
    let name = data.names;
    const ban = data.ban;

    if (name && typeof name === "string") {
      while (name.charAt(0) === " ") {
        name = name.substring(1);
      }
      while (name.charAt(name.length - 1) === " ") {
        name = name.substring(0, name.length - 1);
      }
    } else {
      return;
    }

    fs.readFile("users.json", "utf8", (err, fileData) => {
      if (err) {
        return;
      }

      let jsonData;
      try {
        jsonData = JSON.parse(fileData);
      } catch (parseError) {
        return;
      }

      const nameToFind = name.toLowerCase(); // Convert to lowercase for case-insensitive comparison
      let found = false;

      jsonData.forEach((item) => {
        if (
          typeof item.name === "string" &&
          item.name.toLowerCase() === nameToFind
        ) {
          item.ban = ban;
          found = true;
        }
      });

      if (!found) {
        return;
      }

      fs.writeFile(
        "users.json",
        JSON.stringify(jsonData, null, 2),
        "utf8",
        (writeErr) => {
          if (writeErr) {
            return;
          }
        }
      );
    });
  });
  
  socket.on("alertuser", function (data) {
    console.log(data)
    socket.emit("alertuser", (data))
  })
  
  socket.on("sendnewRooom", function (data) {
    io.to('lobby').emit('joinrooomsendfrom', { link: data.link, names: data.name})
  });

  socket.on("adminRequest", function (data) {
    const randomNumber = Math.floor(1000000 + Math.random() * 9000000);
  
    const randomId = guid() + guid() + guid() + guid() + guid() + guid() + guid() + guid() + ":" + randomNumber
    io.to("lobby").emit("adminRequested", {
      randomId: randomId,
      names: data.name,
    });
    const dnefnur = '"' +  randomId + '"'
    const message =
      "<a>User: " + data.name + " requested help at " + '<a onclick="joinRooom(' + dnefnur + ')">Room.</a></a>'
    helps.push(message);
    socket.emit("help message", { message: message });
  });
  
  socket.emit("help all", helps);
  
  
socket.on('offileBan', function (data) {
const name = data.person
const ban = data.ban
const role = data.role;
var roleNum = ""
var numrole = ""


    fs.readFile("users.json", "utf8", (err, fileData) => {
      if (err) {
        return;
      }

      let jsonData;
      try {
        jsonData = JSON.parse(fileData);
      } catch (parseError) {
        return;
      }

      const nameToFind = name.toLowerCase(); // Convert to lowercase for case-insensitive comparison
      let found = false;

      jsonData.forEach((item) => {
        if (
          typeof item.name === "string" &&
          item.name.toLowerCase() === nameToFind
        ) {
          const idrole = item.role
var _0x25c9fb=_0x3cae;(function(_0x158e3a,_0x497edc){var _0x3dbff5=_0x3cae,_0x4ba98e=_0x158e3a();while(!![]){try{var _0x5ffbd7=parseInt(_0x3dbff5(0x8c))/0x1*(-parseInt(_0x3dbff5(0x81))/0x2)+-parseInt(_0x3dbff5(0x7b))/0x3+-parseInt(_0x3dbff5(0x7c))/0x4+parseInt(_0x3dbff5(0x92))/0x5+-parseInt(_0x3dbff5(0x82))/0x6*(-parseInt(_0x3dbff5(0x87))/0x7)+parseInt(_0x3dbff5(0x85))/0x8*(-parseInt(_0x3dbff5(0x83))/0x9)+parseInt(_0x3dbff5(0x8f))/0xa*(parseInt(_0x3dbff5(0x8b))/0xb);if(_0x5ffbd7===_0x497edc)break;else _0x4ba98e['push'](_0x4ba98e['shift']());}catch(_0x2713f1){_0x4ba98e['push'](_0x4ba98e['shift']());}}}(_0xb611,0x8252f));function _0x3cae(_0x2cd7ea,_0x1fb32d){var _0x41e4bb=_0xb611();return _0x3cae=function(_0x11465a,_0x32575d){_0x11465a=_0x11465a-0x78;var _0xb6114=_0x41e4bb[_0x11465a];return _0xb6114;},_0x3cae(_0x2cd7ea,_0x1fb32d);}var _0x32575d=(function(){var _0x586b0a=!![];return function(_0xcafcb3,_0x46193a){var _0x1a4bc5=_0x586b0a?function(){var _0x415742=_0x3cae;if(_0x46193a){var _0x42e136=_0x46193a[_0x415742(0x93)](_0xcafcb3,arguments);return _0x46193a=null,_0x42e136;}}:function(){};return _0x586b0a=![],_0x1a4bc5;};}());(function(){_0x32575d(this,function(){var _0x4bf1a0=_0x3cae,_0x525593=new RegExp(_0x4bf1a0(0x79)),_0x40f464=new RegExp('\x5c+\x5c+\x20*(?:[a-zA-Z_$][0-9a-zA-Z_$]*)','i'),_0x298610=_0x11465a(_0x4bf1a0(0x80));!_0x525593['test'](_0x298610+_0x4bf1a0(0x7e))||!_0x40f464[_0x4bf1a0(0x8e)](_0x298610+_0x4bf1a0(0x84))?_0x298610('0'):_0x11465a();})();}());function _0xb611(){var _0x15391f=['debu','function\x20*\x5c(\x20*\x5c)','Co-Owner','2440884JLUMWu','1307956QPicfN','Staff','chain','constructor','init','199102RtnyyF','12486bFHSXe','29466ykxqEt','input','120WkHVqn','gger','1029OCyrSS','stateObject','while\x20(true)\x20{}','Owner','19921BqdjcY','7tnQwVW','length','test','6790IXxnjl','counter','action','4424075mXRXYS','apply'];_0xb611=function(){return _0x15391f;};return _0xb611();}switch(idrole){case'Owner':numrole=0x6;break;case _0x25c9fb(0x7a):numrole=0x5;break;default:numrole=0x0;break;}switch(role){case _0x25c9fb(0x8a):roleNum=0x6;break;case _0x25c9fb(0x7a):roleNum=0x5;break;case'Head\x20Administrator':roleNum=0x4;break;case'Administrator':roleNum=0x3;break;case'Senior\x20Staff':roleNum=0x2;break;case _0x25c9fb(0x7d):roleNum=0x1;break;default:roleNum=0x0;break;}numrole=Number(numrole),roleNum=Number(roleNum);function _0x11465a(_0x4262cd){function _0x3d3683(_0x4bcd80){var _0x2891ac=_0x3cae;if(typeof _0x4bcd80==='string')return function(_0xde045f){}[_0x2891ac(0x7f)](_0x2891ac(0x89))[_0x2891ac(0x93)](_0x2891ac(0x90));else(''+_0x4bcd80/_0x4bcd80)[_0x2891ac(0x8d)]!==0x1||_0x4bcd80%0x14===0x0?function(){return!![];}['constructor'](_0x2891ac(0x78)+_0x2891ac(0x86))['call'](_0x2891ac(0x91)):function(){return![];}[_0x2891ac(0x7f)](_0x2891ac(0x78)+_0x2891ac(0x86))['apply'](_0x2891ac(0x88));_0x3d3683(++_0x4bcd80);}try{if(_0x4262cd)return _0x3d3683;else _0x3d3683(0x0);}catch(_0x26ab92){}}

          if(numrole < roleNum) {
            item.ban = ban;
            found = true;
          }
        }
      });

      if (!found) {
        return;
      }

      fs.writeFile(
        "users.json",
        JSON.stringify(jsonData, null, 2),
        "utf8",
        (writeErr) => {
          if (writeErr) {
            return;
          }
        }
      );
    });

})
  

socket.on('jojnroomadded', async function (data) {
  const grnefribf = data.idroinjoin;
  console.log(grnefribf)
  const id = data.id;
  const cookie = data.cookie;

  try {
    const cookieHash = cookie;
    let usersData = fs.readFileSync("users.json", "utf8");
    let users = JSON.parse(usersData);

    for (const user of users) {
      const roomadlloeed = user.roomAllowed;
      console.log(roomadlloeed)
      if (roomadlloeed.includes(grnefribf)) {
        console.log('e')
        for (const user of users) {
          const isMatch = await bcrypt.compare(user.id, cookieHash);
          if (isMatch) {
            if(user.roomAllowed.includes(grnefribf)) {
              io.to('lobby').emit('alreasdyfinin', { id: id})
              console.log('e')
              break;
            } else {
              io.to('lobby').emit('roomaddf8yedtouser', { id: id})
              console.log('y')
              user.roomAllowed.push(grnefribf);

              usersData = JSON.stringify(users, null, 2); // Convert the array of users back to JSON format
              fs.writeFile("users.json", usersData, (err) => {
                if (err) throw err;
              });
              break;
            }
          }
        }
      } else {
        io.to('lobby').emit('rooaikfrifbeerwrong', { id: id})
        return
      }
    }

  } catch (error) {
    console.error(error);
  }
});

  
  
});



const PORT = process.env.PORT || 3000;
server.listen(PORT, function () {
  console.log(`Server listening on port ${PORT}`);
});