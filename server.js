require("dotenv").config();



const express = require("express");

const mongoose = require("mongoose");

const session = require("express-session");

const bcrypt = require("bcryptjs");

const path = require("path");



const app = express();

const PORT = process.env.PORT || 3000;




app.use(express.json());

app.use(express.urlencoded({ extended: true }));


app.set("trust proxy", 1); 

app.use(

  session({

    name: "ems.sid",

    secret: process.env.SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {

      httpOnly: true,

      sameSite: "none",

      secure: process.env.NODE_ENV === "production",

      maxAge: 1000 * 60 * 60

    }

  })

);




const employeeSchema = new mongoose.Schema(

  {

    name: { type: String, required: true, trim: true },

    email: {

      type: String,

      required: true,

      unique: true,

      lowercase: true,

      trim: true

    },

    phone: { type: String, default: "" },

    department: { type: String, default: "" },

    position: { type: String, default: "" },

    salary: { type: Number, default: 0 },

    joinDate: { type: Date, default: Date.now },

    status: { type: String, default: "Active" }

  },

  { timestamps: true }

);



const departmentSchema = new mongoose.Schema(

  {

    name: { type: String, required: true, unique: true, trim: true },

    description: { type: String, default: "" }

  },

  { timestamps: true }

);



const Employee = mongoose.model("Employee", employeeSchema);

const Department = mongoose.model("Department", departmentSchema);

app.get("/api/dashboard", async (req, res) => {

    try {

        const [

            totalEmployees,

            activeEmployees,

            totalDepartments,

            salaryResult,

            recentEmployees

        ] = await Promise.all([

            Employee.countDocuments(),

            Employee.countDocuments({ status: "Active" }),

            Department.countDocuments(),

            Employee.aggregate([

                {

                    $group: {

                        _id: null,

                        total: { $sum: "$salary" }

                    }

                }

            ]),

            Employee.find()

                .sort({ createdAt: -1 })

                .limit(5)

                .select("name email department position salary status joinDate")

                .lean()

        ]);



        res.json({

            totalEmployees,

            activeEmployees,

            totalDepartments,

            totalSalary: salaryResult[0]?.total || 0,

            recentEmployees

        });

    } catch (error) {

        console.error("Dashboard API error:", error);

        res.status(500).json({

            success: false,

            message: "Failed to load dashboard data."

        });

    }

})



function requireAdmin(req, res, next) {

  if (req.session && req.session.isAdmin === true) {

    return next();

  }



  return res.status(401).json({

    success: false,

    message: "Please log in as admin first."

  });

}


app.get("/api/auth/status", (req, res) => {

  res.json({

    loggedIn: req.session?.isAdmin === true,

    username: req.session?.adminUsername || null

  });

});


app.get("/api/auth/setup-status", (req, res) => {

  res.json({

    setupRequired: false

  });

});


app.post("/api/auth/login", async (req, res) => {

  try {

    const { username, password } = req.body;



    if (

      typeof username !== "string" ||

      typeof password !== "string" ||

      !username.trim() ||

      !password

    ) {

      return res.status(400).json({

        success: false,

        message: "Username and password are required."

      });

    }



    const configuredUsername = process.env.ADMIN_USERNAME;

    const passwordHash = process.env.ADMIN_PASSWORD_HASH;



    if (!configuredUsername || !passwordHash) {

      console.error("Admin credentials are missing from .env");

      return res.status(500).json({

        success: false,

        message: "Admin login is not configured. Check the server settings."

      });

    }



    const usernameMatches =

      username.trim() === configuredUsername;



    const passwordMatches = await bcrypt.compare(

      password,

      passwordHash

    );



    if (!usernameMatches || !passwordMatches) {

      return res.status(401).json({

        success: false,

        message: "Invalid username or password."

      });

    }



    // Regenerate session after successful authentication

    req.session.regenerate((error) => {

      if (error) {

        console.error("Session error:", error);

        return res.status(500).json({

          success: false,

          message: "Could not create login session."

        });

      }



      req.session.isAdmin = true;

      req.session.adminUsername = configuredUsername;



      req.session.save((saveError) => {

        if (saveError) {

          console.error("Session save error:", saveError);

          return res.status(500).json({

            success: false,

            message: "Could not save login session."

          });

        }



        res.json({

          success: true,

          message: "Admin login successful.",

          username: configuredUsername

        });

      });

    });

  } catch (error) {

    console.error("Login error:", error);

    res.status(500).json({

      success: false,

      message: "Login failed due to a server error."

    });

  }

});

app.get("/api/auth/me", (req, res) => {

    if (!req.session || !req.session.isAdmin) {

        return res.status(401).json({

            success: false,

            message: "Not authenticated"

        });

    }



    res.json({

        success: true,

        admin: {

            username: req.session.adminUsername

        }

    });

});


app.post("/api/auth/logout", (req, res, next) => {

  req.session.destroy((error) => {

    if (error) {

      return next(error);

    }



    res.clearCookie("ems.sid", {

      httpOnly: true,

      sameSite: "none",

      secure: true,
      maxAge: 1000 * 60 * 60
    

    });



    res.json({

      success: true,

      message: "Logged out successfully."

    });

  });

});


app.get("/api/employees", requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 10));
    const filter = {};

    if (req.query.search) {
      const search = String(req.query.search).trim();
      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        filter.$or = [
          { name: { $regex: escaped, $options: "i" } },
          { email: { $regex: escaped, $options: "i" } },
          { position: { $regex: escaped, $options: "i" } },
          { department: { $regex: escaped, $options: "i" } },
          { employeeId: { $regex: escaped, $options: "i" } }
        ];
      }
    }
    if (req.query.dept) filter.department = String(req.query.dept);
    if (req.query.status) filter.status = String(req.query.status);
    if (req.query.minSalary !== undefined || req.query.maxSalary !== undefined) {
      filter.salary = {};
      if (req.query.minSalary !== undefined && req.query.minSalary !== "") filter.salary.$gte = Number(req.query.minSalary);
      if (req.query.maxSalary !== undefined && req.query.maxSalary !== "") filter.salary.$lte = Number(req.query.maxSalary);
    }

    const [employees, total] = await Promise.all([
      Employee.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Employee.countDocuments(filter)
    ]);

    res.json({ employees, total, page, limit, totalPages: Math.max(1, Math.ceil(total / limit)) });
  } catch (error) {
    console.error("Fetch employees error:", error);
    res.status(500).json({ message: "Could not fetch employees." });
  }
});


app.get("/api/employees/:id", requireAdmin, async (req, res) => {

  try {

    const employee = await Employee.findById(req.params.id);



    if (!employee) {

      return res.status(404).json({ message: "Employee not found." });

    }



    res.json(employee);

  } catch (error) {

    res.status(400).json({ message: "Invalid employee ID." });

  }

});



app.post("/api/employees", requireAdmin, async (req, res) => {
  try {
    const { employeeId, name, email, phone, department, dept, position, salary, joinDate, joinedAt, status } = req.body;

    if (typeof name !== "string" || !name.trim() || typeof email !== "string" || !email.trim()) {
      return res.status(400).json({ message: "Employee name and email are required." });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await Employee.findOne({ email: normalizedEmail }).select("_id").lean();
    if (existing) {
      return res.status(409).json({ message: "An employee with this email already exists.", field: "email" });
    }

    const employee = await Employee.create({
      employeeId: typeof employeeId === "string" ? employeeId.trim() : "",
      name: name.trim(),
      email: normalizedEmail,
      phone: phone || "",
      department: String(department ?? dept ?? "").trim(),
      position: position || "",
      salary: salary === "" || salary == null ? 0 : Number(salary),
      joinDate: joinDate || joinedAt || undefined,
      status: status || "Active"
    });

    res.status(201).json({ success: true, employee });
  } catch (error) {
    console.error("Add employee error:", error);
    if (error.code === 11000) {
      const key = Object.keys(error.keyPattern || error.keyValue || {})[0] || "unknown";
      const isEmail = key === "email";
      return res.status(409).json({
        message: isEmail ? "An employee with this email already exists." : `Duplicate value in field: ${key}. Check the existing database index.`,
        field: key,
        value: error.keyValue?.[key] ?? null
      });
    }
    if (error.name === "ValidationError" || error.name === "CastError") {
      return res.status(400).json({ message: error.message });
    }
    res.status(500).json({ message: "Could not add employee." });
  }
});


app.put("/api/employees/:id", requireAdmin, async (req, res) => {
  try {
    const updates = { ...req.body };
    delete updates._id;
    delete updates.__v;
    delete updates.createdAt;
    delete updates.updatedAt;

    if (updates.dept !== undefined && updates.department === undefined) updates.department = updates.dept;
    if (updates.joinedAt !== undefined && updates.joinDate === undefined) updates.joinDate = updates.joinedAt;
    delete updates.dept;
    delete updates.joinedAt;

    if (updates.email !== undefined) updates.email = String(updates.email).trim().toLowerCase();
    if (updates.name !== undefined) {
      if (typeof updates.name !== "string" || !updates.name.trim()) {
        return res.status(400).json({ message: "Employee name is required." });
      }
      updates.name = updates.name.trim();
    }
    if (updates.salary !== undefined) {
      updates.salary = Number(updates.salary);
      if (!Number.isFinite(updates.salary) || updates.salary < 0) {
        return res.status(400).json({ message: "Enter a valid salary." });
      }
    }

    const employee = await Employee.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
    if (!employee) return res.status(404).json({ message: "Employee not found." });
    res.json({ success: true, employee });
  } catch (error) {
    console.error("Update employee error:", error);
    if (error.code === 11000) {
      const key = Object.keys(error.keyPattern || error.keyValue || {})[0] || "unknown";
      return res.status(409).json({ message: key === "email" ? "An employee with this email already exists." : `Duplicate value in field: ${key}.`, field: key });
    }
    res.status(400).json({ message: "Could not update employee." });
  }
});


app.delete("/api/employees/:id", requireAdmin, async (req, res) => {

  try {

    const employee = await Employee.findByIdAndDelete(req.params.id);



    if (!employee) {

      return res.status(404).json({ message: "Employee not found." });

    }



    res.json({

      success: true,

      message: "Employee deleted successfully."

    });

  } catch (error) {

    res.status(400).json({ message: "Could not delete employee." });

  }

});


app.get("/api/departments", requireAdmin, async (req, res) => {

  try {

    const departments = await Department.find().sort({ name: 1 });

    res.json(departments);

  } catch (error) {

    res.status(500).json({ message: "Could not fetch departments." });

  }

});


app.post("/api/departments", requireAdmin, async (req, res) => {

  try {

    const { name, description } = req.body;



    if (typeof name !== "string" || !name.trim()) {

      return res.status(400).json({

        message: "Department name is required."

      });

    }



    const department = await Department.create({

      name: name.trim(),

      description: description || ""

    });



    res.status(201).json(department);

  } catch (error) {

    if (error.code === 11000) {

      return res.status(409).json({

        message: "This department already exists."

      });

    }



    res.status(500).json({ message: "Could not add department." });

  }

});


app.put("/api/departments/:id", requireAdmin, async (req, res) => {

  try {

    const department = await Department.findById(req.params.id);



    if (!department) {

      return res.status(404).json({ message: "Department not found." });

    }



    const oldName = department.name;

    const updates = { ...req.body };



    delete updates._id;

    delete updates.__v;

    delete updates.createdAt;

    delete updates.updatedAt;



    if (updates.name !== undefined) {

      if (typeof updates.name !== "string" || !updates.name.trim()) {

        return res.status(400).json({

          message: "Department name is required."

        });

      }



      updates.name = updates.name.trim();

    }



    Object.assign(department, updates);

    await department.save();



    // Keep existing employees linked to the renamed department.

    if (updates.name && updates.name !== oldName) {

      await Employee.updateMany(

        { department: oldName },

        { $set: { department: updates.name } }

      );

    }



    res.json(department);

  } catch (error) {

    if (error.code === 11000) {

      return res.status(409).json({

        message: "This department name already exists."

      });

    }



    res.status(400).json({ message: "Could not update department." });

  }

});



// Delete department only if no employees are assigned to it.

app.delete("/api/departments/:id", requireAdmin, async (req, res) => {

  try {

    const department = await Department.findById(req.params.id);



    if (!department) {

      return res.status(404).json({ message: "Department not found." });

    }



    const assignedEmployees = await Employee.countDocuments({

      department: department.name

    });



    if (assignedEmployees > 0) {

      return res.status(409).json({

        message: `Cannot delete this department: ${assignedEmployees} employee(s) are assigned to it.`

      });

    }



    await department.deleteOne();



    res.json({

      success: true,

      message: "Department deleted successfully."

    });

  } catch (error) {

    res.status(400).json({ message: "Could not delete department." });

  }

});


app.use(express.static(path.join(__dirname)));



app.get("/", (req, res) => {

  res.sendFile(path.join(__dirname, "EMS.html"));

});




async function startServer() {

  try {

    if (!process.env.MONGODB_URI) {

      throw new Error("MONGODB_URI is missing from .env");

    }



    if (!process.env.SESSION_SECRET) {

      throw new Error("SESSION_SECRET is missing from .env");

    }



    if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD_HASH) {

      throw new Error("Admin username or password hash is missing from .env");

    }



    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully.");



    app.listen(PORT, () => {

      console.log(`EMS server running at http://localhost:${PORT}`);

    });

  } catch (error) {

    console.error("Server startup failed:", error.message);

    process.exit(1);

  }

}



startServer();